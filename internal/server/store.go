// Copyright 2019 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/nats-io/nats-rest-config-proxy/api"
	"github.com/nats-io/nats-rest-config-proxy/internal/ldap"
	natsserver "github.com/nats-io/nats-server/v2/server"
)

// storePermissionResource
func (s *Server) storePermissionResource(name string, permission *api.Permissions) error {
	path := filepath.Join(s.resourcesDir(), "permissions", fmt.Sprintf("%s.json", name))
	payload, err := permission.AsJSON()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, payload, 0666)
}

// storeUserResource
func (s *Server) storeUserResource(name string, user *api.User) error {
	path := filepath.Join(s.resourcesDir(), "users", fmt.Sprintf("%s.json", name))
	payload, err := user.AsJSON()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, payload, 0666)
}

// storeAccountResource
func (s *Server) storeAccountResource(name string, account *api.Account) error {
	path := filepath.Join(s.resourcesDir(), "accounts", fmt.Sprintf("%s.json", name))
	payload, err := account.AsJSON()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, payload, 0666)
}

// getAllAccountResources reads all account resource files.
func (s *Server) getAllAccountResources() ([]*api.Account, error) {
	root := filepath.Join(s.resourcesDir(), "accounts")
	am := make(map[string]*api.Account)

	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(p) != ".json" {
			// Not an account file, skip.
			return nil
		}

		data, err := ioutil.ReadFile(p)
		if err != nil {
			return err
		}

		var a *api.Account
		if err := json.Unmarshal(data, &a); err != nil {
			return err
		}

		accountName := filepath.Base(strings.TrimSuffix(p, ".json"))
		am[accountName] = a

		return nil
	})
	if err != nil {
		return nil, err
	}

	users, err := s.getUsers()
	if err != nil {
		return nil, err
	}

	// Join Account and User on account name.
	for _, u := range users {
		a, ok := am[u.Account]
		if !ok {
			// User is part of an account that doesn't exist yet.
			continue
		}

		// Add user to the Account's Users field.
		a.Users = append(a.Users, &api.ConfigUser{
			Username: u.Username,
			Password: u.Password,
			Nkey:     u.Nkey,
		})
		am[u.Account] = a
	}

	var as []*api.Account
	for _, a := range am {
		as = append(as, a)
	}
	return as, nil
}

// getAccountResource reads an account resource from a file.
func (s *Server) getAccountResource(name string) (u *api.Account, err error) {
	path := filepath.Join(s.resourcesDir(), "accounts", fmt.Sprintf("%s.json", name))
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &u)
	if err != nil {
		return
	}
	return
}

// deleteAccountResource deletes an account resource from a file.
func (s *Server) deleteAccountResource(name string) error {
	path := filepath.Join(s.resourcesDir(), "accounts", fmt.Sprintf("%s.json", name))
	return os.Remove(path)
}

// getPermissionResource reads a permissions resource from a file
// then returns a set of permissions.
func (s *Server) getPermissionResource(name string) (u *api.Permissions, err error) {
	path := filepath.Join(s.resourcesDir(), "permissions", fmt.Sprintf("%s.json", name))
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &u)
	if err != nil {
		return
	}
	return
}

// getPermissions returns a map of permissions filename to api.Permissions.
func (s *Server) getPermissions() (map[string]*api.Permissions, error) {
	permissions := make(map[string]*api.Permissions)
	files, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "permissions"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))

		p, err := s.getPermissionResource(name)
		if err != nil {
			return nil, err
		}
		permissions[name] = p
	}
	return permissions, nil
}

// getAccounts returns a map of account filename to api.Account.
func (s *Server) getAccounts() (map[string]*api.Account, error) {
	accounts := make(map[string]*api.Account)
	files, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "accounts"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))

		acc, err := s.getAccountResource(name)
		if err != nil {
			return nil, err
		}
		accounts[name] = acc
	}
	return accounts, nil
}

// getUsers returns a set of users.
func (s *Server) getUsers() ([]*api.User, error) {
	users := make([]*api.User, 0)
	files, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "users"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))

		u, err := s.getUserResource(name)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Server) deleteAllUsers() error {
	files, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "users"))
	if err != nil {
		return err
	}
	for _, f := range files {
		path := filepath.Join(s.resourcesDir(), "users", f.Name())
		err := os.Remove(path)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) deleteAllPermissions() (bool, error) {
	var conflict bool
	files, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "permissions"))
	if err != nil {
		return conflict, err
	}
	users, err := s.getUsers()
	if err != nil {
		return conflict, err
	}
	for _, f := range files {
		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))

		// Confirm that no user is using this resource.
		for _, u := range users {
			if u.Permissions == name {
				return true, fmt.Errorf("User %q is using permission %q", u.Username, name)
			}
		}

		// Proceed to remove.
		path := filepath.Join(s.resourcesDir(), "permissions", f.Name())
		err := os.Remove(path)
		if err != nil {
			return conflict, err
		}
	}
	return conflict, nil
}

func (s *Server) deletePermissionResource(name string) error {
	path := filepath.Join(s.resourcesDir(), "permissions", fmt.Sprintf("%s.json", name))
	return os.Remove(path)
}

// getUserResource
func (s *Server) getUserResource(name string) (*api.User, error) {
	path := filepath.Join(s.resourcesDir(), "users", fmt.Sprintf("%s.json", name))
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var u *api.User
	err = json.Unmarshal(data, &u)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Server) deleteUserResource(name string) error {
	path := filepath.Join(s.resourcesDir(), "users", fmt.Sprintf("%s.json", name))
	return os.Remove(path)
}

// getConfigSnapshot
func (s *Server) getConfigSnapshot(name string) ([]byte, error) {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))
	return ioutil.ReadFile(path)
}

// publishConfigSnapshotV2
func (s *Server) publishConfigSnapshotV2(name string) error {
	from := filepath.Join(s.snapshotsDir(), name)
	if _, err := os.Stat(from); err != nil && os.IsNotExist(err) {
		return fmt.Errorf("Snapshot named %q does not exist!", name)
	}
	to := filepath.Join(s.currentConfigDir(), "accounts")

	// First remove the contents of the folder in case there is anything.
	err := os.RemoveAll(to)
	if err != nil {
		return err
	}
	cmd := exec.Command("cp", "-rf", from, to)
	return cmd.Run()
}

func (s *Server) deleteConfigSnapshot(name string) error {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))
	return os.Remove(path)
}

func (s *Server) deleteConfigSnapshotV2(name string) error {
	snapDir := filepath.Join(s.snapshotsDir(), name)
	return os.RemoveAll(snapDir)
}

// buildConfigSnapshot will create the configuration with the users and permission
// including the accounts.
func (s *Server) buildConfigSnapshot(name string) error {
	permissions, err := s.getPermissions()
	if err != nil {
		return err
	}

	// Users that belong to the global account.
	users := make([]*api.ConfigUser, 0)
	accounts := make(map[string]*api.Account)
	files, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "users"))
	if err != nil {
		return err
	}
	for _, f := range files {
		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))

		u, err := s.getUserResource(name)
		if err != nil {
			return err
		}
		p, ok := permissions[u.Permissions]
		if !ok {
			s.log.Warnf("User %q will use default permissions", u.Username)
		}
		user := &api.ConfigUser{
			Permissions: p,
		}
		if u.Username != "" {
			user.Username = u.Username
		}
		if u.Nkey != "" {
			user.Nkey = u.Nkey
		}
		if u.Password != "" {
			user.Password = u.Password
		}

		if u.Account != "" {
			account, ok := accounts[u.Account]
			if !ok {
				// Look for the info from this account.
				acc, err := s.getAccountResource(u.Account)
				if err != nil {
					return err
				}
				ausers := make([]*api.ConfigUser, 0)
				account = &api.Account{
					Users:     ausers,
					Exports:   acc.Exports,
					Imports:   acc.Imports,
					JetStream: acc.JetStream,
					Mappings:  acc.Mappings,
				}
				accounts[u.Account] = account
			}
			// Add the user to the account.
			account.Users = append(account.Users, user)
		} else {
			users = append(users, user)
		}
	}

	ac := &api.AuthConfig{
		Users:    users,
		Accounts: accounts,
	}
	conf, err := ac.AsJSON()
	if err != nil {
		return err
	}
	err = s.storeSnapshot(name, conf)
	if err != nil {
		return err
	}

	return nil
}

// buildConfigSnapshotV2 will create the configuration with the users and permission
// including the accounts.
func (s *Server) buildConfigSnapshotV2(snapshotName string) error {
	// Load permissions map for the users
	permissions, err := s.getPermissions()
	if err != nil {
		return err
	}

	// Load each one of the accounts, then we will lookup the
	// users to belong to each account.
	accounts, err := s.getAccounts()
	if err != nil {
		return err
	}

	// Reduce the users into the account, then explode the accounts
	// by iterating at the end.
	userFiles, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "users"))
	if err != nil {
		return err
	}

	// Convert api.User to api.ConfigUser.
	var globalUsers []*api.ConfigUser
	for _, f := range userFiles {
		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))
		u, err := s.getUserResource(name)
		if err != nil {
			return err
		}

		// Lookup the permissions file this user has specified.
		p, ok := permissions[u.Permissions]
		if !ok {
			// User will use default permissions.
		}
		user := &api.ConfigUser{
			Permissions: p,
		}

		if u.Username != "" {
			user.Username = u.Username
		}
		if u.Nkey != "" {
			user.Nkey = u.Nkey
		}
		if u.Password != "" {
			user.Password = u.Password
		}

		if u.Account != "" {
			account, ok := accounts[u.Account]
			if !ok {
				return fmt.Errorf("account %s does not exist!", u.Account)
			}

			// Add the user to the account.
			account.Users = append(account.Users, user)
			accounts[u.Account] = account
		} else {
			globalUsers = append(globalUsers, user)
		}
	}

	// Create directory for this snapshot if not present and
	// write a file for each one of the accounts that is
	// later referenced as an include.
	snapDir := filepath.Join(s.snapshotsDir(), snapshotName)
	if err := os.MkdirAll(snapDir, 0755); err != nil {
		return err
	}

	var authContent string
	for accName, account := range accounts {
		if accName != "" && !isValidName(accName) {
			return fmt.Errorf("Invalid characters in account name: %q, cannot include any of the following characters: \\t\\r\\n\\f.*>", accName)
		}
		account.Users = mergeDuplicateUsers(account.Users)

		if account.JetStream != nil && account.JetStream.Enabled {
			// NOTE: We are disabling here in order to prevent
			// enabled field from becoming part of the NATS config.
			account.JetStream.Enabled = false
		}

		// Store each one of the accounts here.
		acc, err := account.AsJSON()
		if err != nil {
			return err
		}
		err = s.storeAccountSnapshot(snapshotName, accName, acc)
		if err != nil {
			return err
		}
		authContent += fmt.Sprintf("  %s { include '%s.json' }\n", accName, accName)
	}

	globalUsers = mergeDuplicateUsers(globalUsers)

	// Find duplicate DN users across accounts and in the global account
	// to prevent ambiguous permissions.
	// FIXME: Improve this lookup...
	findDups := func(accName string, dns *[]*dnUser, users []*api.ConfigUser) error {
		for _, u := range users {
			user := u
			currentDN, err := ldap.ParseDN(u.Username)
			if err == nil && u.Username != "" {
				// Collect valid DNs and find any other matching DN.
				for _, prevDN := range *dns {
					if prevDN.dn.RDNsMatch(currentDN) {
						details := fmt.Sprintf("User %q from Account %q also defined as %q on Account: %v", prevDN.user.Username, prevDN.account, user.Username, accName)
						return fmt.Errorf("Found duplicated DN based users on multiple accounts! Details: %s", details)
					}
				}
				*dns = append(*dns, &dnUser{
					dn:      currentDN,
					user:    user,
					account: accName,
				})
			}
		}
		return nil
	}

	dns := make([]*dnUser, 0)
	for accName, account := range accounts {
		err := findDups(accName, &dns, account.Users)
		if err != nil {
			return err
		}
	}
	err = findDups("$G", &dns, globalUsers)
	if err != nil {
		return err
	}

	var includeJetStreamConf bool
	jsc, err := s.getGlobalJetStream()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err == nil {
		includeJetStreamConf = true
		data, err := marshalIndent(jsc)
		if err != nil {
			return err
		}
		if err := s.storeGlobalJetStreamSnapshot(snapshotName, data); err != nil {
			return err
		}
	}

	// Create the include file
	var authIncludes string
	if len(globalUsers) > 0 {
		type globalUsersConfig struct {
			Users []*api.ConfigUser `json:"users"`
		}
		gusers := &globalUsersConfig{
			Users: globalUsers,
		}

		u, err := marshalIndent(gusers)
		if err != nil {
			return err
		}
		err = s.storeAccountSnapshot(snapshotName, "global", u)
		if err != nil {
			return err
		}
	}

	authIncludes += fmt.Sprintf("accounts {\n%s\n}\n", authContent)
	if includeJetStreamConf {
		authIncludes += fmt.Sprintf("jetstream {\n  include %q\n}\n", "jetstream.json")
	}

	err = s.storeSnapshotConfigV2(snapshotName, []byte(authIncludes))
	if err != nil {
		return err
	}

	return s.validateSnapshotConfigV2(snapshotName)
}

type dnUser struct {
	dn      *ldap.DN
	user    *api.ConfigUser
	account string
}

// mergeDuplicateUsers takes an array of users and merges the permissions of
// users that have the same name. The caller should make sure that all of the
// users in the given array are from the same account.
func mergeDuplicateUsers(users []*api.ConfigUser) []*api.ConfigUser {
	m := make(map[string]*api.ConfigUser)
	dns := make([]*dnUser, 0)

	for _, u := range users {
		user := u
		currentDN, err := ldap.ParseDN(u.Username)
		if err == nil && u.Username != "" {
			// Collect valid DNs and find any other matching DN.
			match := false
			for i, prevDN := range dns {
				if prevDN.dn.RDNsMatch(currentDN) {
					// Merge the user permissions.
					p := mergeUserPermissions(
						prevDN.user.Permissions,
						u.Permissions,
					)
					prevDN.user.Permissions = p
					dns[i] = prevDN
					match = true
				}
			}

			// If no match, then add it.
			if !match {
				dns = append(dns, &dnUser{
					dn:   currentDN,
					user: user,
				})
			}
		} else {
			key := u.Username + u.Password + u.Nkey

			// Plain check
			if prev, ok := m[key]; ok {
				// Found a duplicate!
				p := mergeUserPermissions(prev.Permissions, u.Permissions)
				prev.Permissions = p

				// Keep original. It shouldn't matter which we keep because only
				// the permissions should be different.
				m[key] = prev
				continue
			}
			// Not seen before, keep track.
			m[key] = u
		}
	}
	deduped := make([]*api.ConfigUser, 0, len(m))
	for _, user := range m {
		deduped = append(deduped, user)
	}

	// Also add deduped DN like entries.
	for _, dn := range dns {
		deduped = append(deduped, dn.user)
	}

	return deduped
}

func mergeUserPermissions(a, b *api.Permissions) *api.Permissions {
	if a == nil && b == nil {
		return nil
	}

	var (
		publish   *api.PermissionRules
		subscribe *api.PermissionRules
	)
	if a.Publish == nil {
		publish = b.Publish
	} else if b.Publish == nil {
		publish = a.Publish
	} else {
		publish = mergePermissionRules(a.Publish, b.Publish)
	}

	if a.Subscribe == nil {
		subscribe = b.Subscribe
	} else if b.Subscribe == nil {
		subscribe = a.Subscribe
	} else {
		subscribe = mergePermissionRules(a.Subscribe, b.Subscribe)
	}
	return &api.Permissions{
		Publish:   publish,
		Subscribe: subscribe,
	}
}

func mergePermissionRules(a, b *api.PermissionRules) *api.PermissionRules {
	if a == nil && b == nil {
		return nil
	}

	allow := mergeStringSlices(a.Allow, b.Allow)
	deny := mergeStringSlices(a.Deny, b.Deny)

	return &api.PermissionRules{
		Allow: allow,
		Deny:  deny,
	}
}

func mergeStringSlices(a, b []string) []string {
	m := make(map[string]struct{})
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		m[s] = struct{}{}
	}

	if len(m) == 0 {
		return nil
	}

	dd := make([]string, 0, len(m))
	for s := range m {
		dd = append(dd, s)
	}

	sort.Strings(dd)
	return dd
}

func (s *Server) validateSnapshotConfigV2(name string) error {
	pt := filepath.Join(s.snapshotsDir(), name)
	p := filepath.Join(pt, "auth.conf")
	_, e := natsserver.ProcessConfigFile(p)
	if e == nil {
		return nil
	}

	// If there were any errors try to find the position
	// of the resulting error.
	fields := strings.Split(e.Error(), ":")
	if len(fields) >= 3 {
		// Try to get the line with the error.
		path := fields[0]
		lineNumber, err := strconv.Atoi(fields[1])
		if err != nil {
			goto ReportError
		}

		spaces, err := strconv.Atoi(fields[2])
		if err != nil {
			goto ReportError
		}

		configErr := fields[3]
		r, err := os.Open(path)
		if err != nil {
			goto ReportError
		}

		output := ""
		sc := bufio.NewScanner(r)
		for i := 0; sc.Scan(); i++ {
			output += sc.Text()
			if i == lineNumber {
				whitespace := strings.Repeat(" ", spaces)
				output += fmt.Sprintf("\n%s^^^ %s\n", whitespace, configErr)
				break
			} else {
				output += "\n"
			}
		}
		return fmt.Errorf("On %s : %s", strings.Replace(path, pt, "", -1), output)
	}

ReportError:
	if e != nil {
		return errors.New(strings.Replace(e.Error(), pt, "", -1))
	}
	return nil
}

func (s *Server) storeSnapshot(name string, payload []byte) error {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))
	return ioutil.WriteFile(path, payload, 0666)
}

func (s *Server) storeSnapshotConfigV2(name string, payload []byte) error {
	path := filepath.Join(s.snapshotsDir(), name, "auth.conf")
	return ioutil.WriteFile(path, payload, 0666)
}

func (s *Server) storeConfigV2(data []byte) error {
	path := filepath.Join(s.currentConfigDir(), "auth.conf")
	return ioutil.WriteFile(path, data, 0666)
}

func (s *Server) storeConfig(data []byte) error {
	path := filepath.Join(s.currentConfigDir(), "auth.json")
	return ioutil.WriteFile(path, data, 0666)
}

func (s *Server) storeAccountSnapshot(snapshotName string, accName string, payload []byte) error {
	path := filepath.Join(s.snapshotsDir(), snapshotName, fmt.Sprintf("%s.json", accName))
	return ioutil.WriteFile(path, payload, 0666)
}

func (s *Server) getCurrentConfig() ([]byte, error) {
	path := filepath.Join(s.currentConfigDir(), "auth.json")
	return ioutil.ReadFile(path)
}

func (s *Server) setupStoreDirectories() error {
	if err := os.MkdirAll(s.currentConfigDir(), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(s.snapshotsDir(), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.resourcesDir(), "users"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.resourcesDir(), "permissions"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.resourcesDir(), "accounts"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.resourcesDir(), "jetstream"), 0755); err != nil {
		return err
	}
	return nil
}

func (s *Server) storeGlobalJetStream(c *api.GlobalJetStream) error {
	data, err := marshalIndent(c)
	if err != nil {
		return err
	}

	path := filepath.Join(s.resourcesDir(), "jetstream", "jetstream.json")
	return ioutil.WriteFile(path, data, 0666)
}

func (s *Server) storeGlobalJetStreamSnapshot(name string, payload []byte) error {
	path := filepath.Join(s.snapshotsDir(), name, "jetstream.json")
	return ioutil.WriteFile(path, payload, 0666)
}

func (s *Server) getGlobalJetStream() (*api.GlobalJetStream, error) {
	path := filepath.Join(s.resourcesDir(), "jetstream", "jetstream.json")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c *api.GlobalJetStream
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}

	return c, nil
}

func (s *Server) deleteGlobalJetStream() error {
	path := filepath.Join(s.resourcesDir(), "jetstream", "jetstream.json")
	return os.Remove(path)
}

// RunDataDirectoryRepair fixes the data directory in case there are duplicates.
// This function is meant to be run in a standalone.
func (s *Server) RunDataDirectoryRepair() error {
	if s.log == nil {
		l := NewLogger(s.opts)
		l.debug = s.opts.Debug
		l.trace = s.opts.Trace
		if s.opts.NoLog {
			l.logger.SetOutput(ioutil.Discard)
		}
		s.log = l
	}
	files, err := filepath.Glob(filepath.Join(s.opts.DataDir, "*.json"))
	if err != nil {
		return err
	}
	// Find duplicate entries in the output directory.
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var a *api.Account
		if err := json.Unmarshal(data, &a); err != nil {
			return err
		}
		users := mergeDuplicateUsers(a.Users)
		delta := len(a.Users) - len(users)
		if delta > 0 {
			s.log.Infof("Found %d duplicate users at account %q\n", delta, file)
		} else {
			// Skip since no changes.
			s.log.Tracef("No duplicates at account %q\n", file)
			continue
		}
		a.Users = users
		acc, err := a.AsJSON()
		if err != nil {
			return err
		}
		err = os.WriteFile(file, acc, 0666)
		if err != nil {
			return err
		}
	}

	p := filepath.Join(s.opts.DataDir, "auth.conf")
	_, err = natsserver.ProcessConfigFile(p)
	if err != nil {
		return err
	}

	return nil
}
