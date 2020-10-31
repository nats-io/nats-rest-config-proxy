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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats-rest-config-proxy/api"
)

// HandlePerm handles a request to create/update permissions.
func (s *Server) HandlePerm(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	name := strings.TrimPrefix(req.URL.Path, "/v1/auth/perms/")

	// PUT
	switch req.Method {
	case "PUT":
		s.log.Infof("Updating permission resource %q", name)
		var payload []byte
		payload, err = ioutil.ReadAll(req.Body)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		size = len(payload)

		// Validate that it is a permission
		var p *api.Permissions
		err = json.Unmarshal(payload, &p)
		if err != nil {
			status = http.StatusBadRequest
			return
		}
		s.log.Tracef("Permission %q: %+v", name, p)

		// Should get a type here instead
		err = s.storePermissionResource(name, p)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "Perm: %s\n", name)
	case "GET":
		s.log.Debugf("Retrieving permission resource %q", name)
		var resource *api.Permissions
		resource, err = s.getPermissionResource(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		var payload []byte
		payload, err = resource.AsJSON()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprint(w, string(payload))
	case "DELETE":
		s.log.Debugf("Deleting permission resource %q", name)
		if name == "" {
			err = errors.New("Bad Request")
			status = http.StatusBadRequest
			return
		}

		// Confirm that no user is using this resource.
		var users []*api.User
		users, err = s.getUsers()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		for _, u := range users {
			if u.Permissions == name {
				err = fmt.Errorf("User %q is using permission %q", u.Username, name)
				status = http.StatusConflict
				return
			}
		}

		err = s.deletePermissionResource(name)
		if err != nil {
			if os.IsNotExist(err) {
				status = http.StatusNotFound
			} else {
				status = http.StatusInternalServerError
			}
			return
		}
		fmt.Fprintf(w, "Deleted permission resource %q", name)
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandleIdent
func (s *Server) HandleIdent(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	name := strings.TrimPrefix(req.URL.Path, "/v1/auth/idents/")

	switch req.Method {
	case "PUT":
		s.log.Infof("Updating user resource %q", name)
		var payload []byte
		payload, err = ioutil.ReadAll(req.Body)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		size = len(payload)

		// Validate that it is a user
		var u *api.User
		err = json.Unmarshal(payload, &u)
		if err != nil {
			status = http.StatusBadRequest
			return
		}

		var existing []*api.User
		existing, err = s.getUsers()
		if err != nil {
			status = http.StatusBadRequest
			return
		}
		if err = verifyIdent(existing, u); err != nil {
			status = http.StatusConflict
			return
		}

		// Store permission
		s.log.Tracef("User %q: %+v", name, u)
		err = s.storeUserResource(name, u)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		var msg string
		if u.Account != "" {
			msg = fmt.Sprintf("User %q on %q account updated\n", name, u.Account)
		} else {
			msg = fmt.Sprintf("User %q on global account updated\n", name)
		}
		fmt.Fprintf(w, msg)
	case "GET":
		s.log.Debugf("Retrieving user resource %q", name)

		var resource *api.User
		resource, err = s.getUserResource(name)
		if err != nil {
			if os.IsNotExist(err) {
				status = http.StatusNotFound
			} else {
				status = http.StatusInternalServerError
			}

			return
		}
		var js []byte
		js, err = resource.AsJSON()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprint(w, string(js))
	case "DELETE":
		s.log.Debugf("Deleting user resource %q", name)
		if name == "" {
			err = errors.New("Bad Request")
			status = http.StatusBadRequest
			return
		}

		err = s.deleteUserResource(name)
		if err != nil {
			if os.IsNotExist(err) {
				status = http.StatusNotFound
			} else {
				status = http.StatusInternalServerError
			}
			return
		}
		fmt.Fprintf(w, "Deleted user resource %q", name)
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

func verifyIdent(existing []*api.User, nu *api.User) error {
	for _, eu := range existing {
		if eu.Username != nu.Username {
			continue
		}
		// User is existing user.

		// A user can only belong to one account. To move a user, delete the
		// old user and create again. Since Usernames are optional, we need to
		// only do this check if a Username was used.
		if eu.Username != "" && eu.Account != nu.Account {
			return fmt.Errorf("%q already exists in different account", nu.Username)
		}
	}

	return nil
}

// HandleSnapshot
func (s *Server) HandleSnapshot(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	name := req.URL.Query().Get("name")
	if name == "" {
		name = DefaultSnapshotName
	}
	switch req.Method {
	case "POST":
		s.log.Infof("Creating config snapshot %q", name)
		err = s.buildConfigSnapshot(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "Config snapshot %q created\n", name)
	case "GET":
		var data []byte
		data, err = s.getConfigSnapshot(name)
		if err != nil {
			if os.IsNotExist(err) {
				status = http.StatusNotFound
				return
			}
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, string(data))
	case "DELETE":
		s.log.Infof("Deleting config snapshot %q", name)
		err = s.deleteConfigSnapshot(name)
		if err != nil {
			if os.IsNotExist(err) {
				status = http.StatusNotFound
			} else {
				status = http.StatusInternalServerError
			}
			return
		}
		fmt.Fprintf(w, "OK\n")
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandlePublish
func (s *Server) HandlePublish(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	name := req.URL.Query().Get("name")
	if name == "" {
		s.log.Infof("Building latest config...")
		name = DefaultSnapshotName
		err = s.buildConfigSnapshot(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
	} else {
		s.log.Infof("Creating config from snapshot %q", name)
	}
	switch req.Method {
	case "POST":
		var data []byte
		data, err = s.getConfigSnapshot(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		err = s.storeConfig(data)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}

		s.mu.Lock()
		script := s.opts.PublishScript
		s.mu.Unlock()

		if script != "" {
			// Change the cwd of the command to location of the script.
			var stdout, stderr bytes.Buffer
			cmd := exec.Command(script)
			cmd.Dir = filepath.Dir(script)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			s.log.Infof("Executing publish script %q", script)
			err = cmd.Run()
			s.log.Tracef("STDOUT: %s", stdout.String())
			s.log.Tracef("STDERR: %s", stdout.String())
			if err != nil {
				status = http.StatusInternalServerError
				return
			}
		}

		fmt.Fprintf(w, "Configuration published\n")
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandlePerms
func (s *Server) HandlePerms(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	switch req.Method {
	case "GET":
		var (
			data  []byte
			perms map[string]*api.Permissions
		)
		perms, err = s.getPermissions()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		data, err = marshalIndent(perms)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, string(data))
		return
	case "DELETE":
		var conflict bool
		conflict, err = s.deleteAllPermissions()
		if err != nil {
			if conflict {
				status = http.StatusConflict
			} else {
				status = http.StatusInternalServerError
			}
			return
		}
		fmt.Fprintf(w, "OK\n")
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
		return
	}
}

// HandleIdents
func (s *Server) HandleIdents(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	switch req.Method {
	case "GET":
		var (
			data  []byte
			users []*api.User
		)
		users, err = s.getUsers()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		data, err = marshalIndent(users)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, string(data))
		return
	case "DELETE":
		err = s.deleteAllUsers()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "OK\n")
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
		return
	}
}

func hasWildcard(s string) bool {
	return strings.Contains(s, ">") || strings.Contains(s, "*")
}

// HandleAccounts
func (s *Server) HandleAccounts(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	name := strings.TrimPrefix(req.URL.Path, "/v1/auth/accounts/")
	switch req.Method {
	case "PUT":
		s.log.Infof("Updating account resource %q", name)
		var payload []byte
		payload, err = ioutil.ReadAll(req.Body)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		size = len(payload)

		// If no payload, just create an empty object that
		// will help create the account.
		var a *api.Account
		if size == 0 {
			a = &api.Account{}
		} else {
			err = json.Unmarshal(payload, &a)
			if err != nil {
				status = http.StatusBadRequest
				return
			}
		}

		// Validate that the metadata from the account is ok.
		//
		// - Check that the accounts in the imports have been defined
		// - Check that the imports are correct and offered by the
		//   other account.
		//

		if len(a.Users) > 0 {
			err = fmt.Errorf("Users are not allowed to be defined in payload")
			status = http.StatusBadRequest
			return
		}

		// Verify imports and exports and prevent bad requests.
		hasExports := a.Exports != nil
		hasImports := a.Imports != nil
		if hasExports {
			// Check whether the exports have explicitly defined with
			// which accounts the stream/service can be shared.
			for _, exp := range a.Exports {
				if exp.Stream == "" && exp.Service == "" {
					err = fmt.Errorf("Stream or service must be defined in export")
					status = http.StatusBadRequest
					return
				}

				for _, acc := range exp.Accounts {
					if _, err = s.getAccountResource(acc); err != nil {
						if os.IsNotExist(err) {
							err = fmt.Errorf("Account %q defined in export does not exist", acc)
							status = http.StatusNotFound
						} else {
							status = http.StatusInternalServerError
						}
						return
					}
				}
			}
		}
		if hasImports {
			for _, imp := range a.Imports {
				hasService := imp.Service != nil
				hasStream := imp.Stream != nil

				switch {
				case hasService && hasStream:
					err = fmt.Errorf("Import must define either service or stream, but not both")
					status = http.StatusBadRequest
					return
				case hasService:
					if imp.Service.Account == "" {
						err = fmt.Errorf("Import must have service account defined")
						status = http.StatusBadRequest
						return
					}
					if imp.Service.Subject == "" {
						err = fmt.Errorf("Import must have service subject defined")
						status = http.StatusBadRequest
						return
					}
					if hasWildcard(imp.Service.Subject) {
						err = fmt.Errorf("Import service subject must not have a wildcard")
						status = http.StatusBadRequest
						return
					}

					acc := imp.Service.Account
					if _, err = s.getAccountResource(acc); err != nil {
						if os.IsNotExist(err) {
							err = fmt.Errorf("Account %q defined in export does not exist", acc)
							status = http.StatusNotFound
						} else {
							status = http.StatusInternalServerError
						}
						return
					}
				case hasStream:
					if imp.Stream.Account == "" {
						err = fmt.Errorf("Import must have stream account defined")
						status = http.StatusBadRequest
						return
					}
					if imp.Stream.Subject == "" {
						err = fmt.Errorf("Import must have stream subject defined")
						status = http.StatusBadRequest
						return
					}

					acc := imp.Stream.Account
					if _, err = s.getAccountResource(acc); err != nil {
						if os.IsNotExist(err) {
							err = fmt.Errorf("Account %q defined in export does not exist", acc)
							status = http.StatusNotFound
						} else {
							status = http.StatusInternalServerError
						}
						return
					}
				default:
					err = fmt.Errorf("Import is missing services or streams")
					status = http.StatusBadRequest
					return
				}
			}
		}

		// Store account information
		s.log.Tracef("Account %q: %+v", name, a)
		err = s.storeAccountResource(name, a)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "OK\n")
	case "GET":
		s.log.Debugf("Retrieving account resource %q", name)
		if name == "" {
			// If name == "", then URL is a GET request on an entire
			// collection.
			var resources []*api.Account
			resources, err = s.getAllAccountResources()
			if err != nil {
				status = http.StatusInternalServerError
				return
			}

			var objs []string
			var js []byte
			for _, r := range resources {
				js, err = r.AsJSON()
				if err != nil {
					status = http.StatusInternalServerError
					return
				}
				objs = append(objs, string(js))
			}
			fmt.Fprintf(w, "[%v]", strings.Join(objs, ","))
			return
		}

		var resource *api.Account
		resource, err = s.getAccountResource(name)
		if err != nil {
			if os.IsNotExist(err) {
				err = fmt.Errorf("Account %q does not exist", name)
				status = http.StatusNotFound
			} else {
				status = http.StatusInternalServerError
			}
			return
		}
		var payload []byte
		payload, err = resource.AsJSON()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprint(w, string(payload))
	case "DELETE":
		s.log.Debugf("Deleting account resource %q", name)
		if name == "" {
			err = fmt.Errorf("Account name required for DELETE")
			status = http.StatusBadRequest
			return
		}

		// Confirm that no user is using this resource.
		var users []*api.User
		users, err = s.getUsers()
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		for _, u := range users {
			if u.Account == name {
				err = fmt.Errorf("User %q is using account %q", u.Username, name)
				status = http.StatusConflict
				return
			}
		}

		err = s.deleteAccountResource(name)
		if err != nil {
			if os.IsNotExist(err) {
				status = http.StatusNotFound
			} else {
				status = http.StatusInternalServerError
			}
			return
		}
		fmt.Fprintf(w, "Deleted permission resource %q", name)
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandleSnapshotV2
func (s *Server) HandleSnapshotV2(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	name := req.URL.Query().Get("name")
	if name == "" {
		name = DefaultSnapshotName
	}

	switch req.Method {
	case "POST":
		s.log.Infof("Building latest config...")
		err = s.buildConfigSnapshotV2(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		s.log.Infof("Creating config from snapshot %q", name)

		fmt.Fprintf(w, "Configuration published\n")
	case "GET":
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	case "DELETE":
		s.log.Infof("Deleting config snapshot %q", name)
		err = s.deleteConfigSnapshotV2(name)
		if err != nil {
			if os.IsNotExist(err) {
				status = http.StatusNotFound
			} else {
				status = http.StatusInternalServerError
			}
			return
		}
		fmt.Fprintf(w, "OK\n")
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandleValidateSnapshotV2
func (s *Server) HandleValidateSnapshotV2(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	if req.Method != "POST" {
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
		return
	}

	s.log.Infof("Building latest config...")
	if err = s.VerifySnapshot(); err != nil {
		status = http.StatusInternalServerError
		return
	}

	fmt.Fprintf(w, "OK\n")
}

func (s *Server) VerifySnapshot() error {
	name := randomString(32)

	if err := s.buildConfigSnapshotV2(name); err != nil {
		defer s.deleteConfigSnapshotV2(name)
		return err
	}

	return s.deleteConfigSnapshotV2(name)
}

func (s *Server) TakeSnapshot(name string) error {
	return s.buildConfigSnapshotV2(name)
}

func (s *Server) PublishSnapshot(name string) error {
	return s.publishConfigSnapshotV2(name)
}

func randomString(n int) string {
	a := 97
	z := 122

	var buf strings.Builder
	for i := 0; i < n; i++ {
		buf.WriteByte(byte(randIntRange(a, z)))
	}

	return buf.String()
}

func randIntRange(min, max int) int {
	return rand.Intn(max-min) + min
}

// HandlePublishV2
func (s *Server) HandlePublishV2(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}

	switch req.Method {
	case "POST":
		name := req.URL.Query().Get("name")
		if name == "" {
			s.log.Infof("Building latest config...")
			name = DefaultSnapshotName
			err = s.buildConfigSnapshotV2(name)
			if err != nil {
				status = http.StatusInternalServerError
				return
			}
		} else {
			s.log.Infof("Creating config from snapshot %q", name)
		}

		err = s.publishConfigSnapshotV2(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}

		s.mu.Lock()
		script := s.opts.PublishScript
		s.mu.Unlock()

		if script != "" {
			// Change the cwd of the command to location of the script.
			var stdout, stderr bytes.Buffer
			cmd := exec.Command(script)
			cmd.Dir = filepath.Dir(script)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			s.log.Infof("Executing publish script %q", script)
			err = cmd.Run()
			s.log.Tracef("STDOUT: %s", stdout.String())
			s.log.Tracef("STDERR: %s", stderr.String())
			if err != nil {
				status = http.StatusInternalServerError
				return
			}
		}

		fmt.Fprintf(w, "Configuration published\n")
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandleHealthz handles healthz.
func (s *Server) HandleHealthz(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()
	err = s.verifyAuth(w, req)
	if err != nil {
		status = http.StatusUnauthorized
		return
	}
	fmt.Fprintf(w, "OK\n")
}

func (s *Server) verifyAuth(w http.ResponseWriter, req *http.Request) error {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		cert := req.TLS.PeerCertificates[0]
		subject := cert.Subject.String()
		s.log.Debugf("Verifying TLS Cert with Subject %q", subject)
		for _, user := range s.opts.HTTPUsers {
			if user == subject {
				return nil
			}
		}
		return errors.New("authorization failed")
	}

	return nil
}

func (s *Server) processErr(err error, status int, w http.ResponseWriter, req *http.Request) {
	if err != nil {
		errMsg := fmt.Sprintf("Error: %s", err)
		s.log.Errorf(errMsg)
		http.Error(w, errMsg, status)
	}
}

func marshalIndent(v interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	if err != nil {
		return nil, err
	}
	buf2 := &bytes.Buffer{}
	err = json.Indent(buf2, buf.Bytes(), "", "  ")
	if err != nil {
		return nil, err
	}
	return buf2.Bytes(), nil
}
