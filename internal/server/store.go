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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
)

// storePermissionResource
func (s *Server) storePermissionResource(name string, payload []byte) error {
	path := filepath.Join(s.resourcesDir(), "permissions", fmt.Sprintf("%s.json", name))
	return ioutil.WriteFile(path, payload, 0666)
}

// storeUserResource
func (s *Server) storeUserResource(name string, payload []byte) error {
	path := filepath.Join(s.resourcesDir(), "users", fmt.Sprintf("%s.json", name))
	return ioutil.WriteFile(path, payload, 0666)
}

// getPermissionResource
func (s *Server) getPermissionResource(name string) ([]byte, error) {
	path := filepath.Join(s.resourcesDir(), "permissions", fmt.Sprintf("%s.json", name))
	return ioutil.ReadFile(path)
}

// getUserResource
func (s *Server) getUserResource(name string) ([]byte, error) {
	path := filepath.Join(s.resourcesDir(), "users", fmt.Sprintf("%s.json", name))
	return ioutil.ReadFile(path)
}

// getConfigSnapshot
func (s *Server) getConfigSnapshot(name string) ([]byte, error) {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))
	return ioutil.ReadFile(path)
}

type User struct {
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Nkey        string `json:"nkey,omitempty"`
	Permissions string `json:"permissions,omitempty"`
}

type ExpandedUser struct {
	Username    string       `json:"username,omitempty"`
	Password    string       `json:"password,omitempty"`
	Nkey        string       `json:"nkey,omitempty"`
	Permissions *Permissions `json:"permissions,omitempty"`
}

type Permissions struct {
	Publish   *PermissionRules `json:"publish,omitempty"`
	Subscribe *PermissionRules `json:"subscribe,omitempty"`
}

type PermissionRules struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

type AuthConfig struct {
	Users []*ExpandedUser `json:"users"`
}

// buildConfigSnapshot
func (s *Server) buildConfigSnapshot(name string) error {
	// Collect the files
	permissions := make(map[string]*Permissions)
	users := make([]*ExpandedUser, 0)

	files, err := ioutil.ReadDir(filepath.Join(s.resourcesDir(), "permissions"))
	if err != nil {
		return err
	}
	s.log.Debugf("result: %+v", files)
	for _, f := range files {
		s.log.Debugf("permission: %+v", f.Name())

		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))

		// Read the file and try to create a user
		data, err := s.getPermissionResource(name)
		if err != nil {
			return err
		}
		s.log.Debugf("=============== %+v", string(data))
		var p *Permissions
		err = json.Unmarshal(data, &p)
		if err != nil {
			return err
		}
		permissions[name] = p
	}
	s.log.Debugf("permissions: %+v", permissions)

	files, err = ioutil.ReadDir(filepath.Join(s.resourcesDir(), "users"))
	if err != nil {
		return err
	}
	s.log.Debugf("result: %+v", files)
	for _, f := range files {
		s.log.Debugf("permission: %+v", f.Name())

		basename := f.Name()
		name := strings.TrimSuffix(basename, filepath.Ext(basename))
		data, err := s.getUserResource(name)
		if err != nil {
			return err
		}
		s.log.Debugf("=============== %+v", string(data))
		var u *User
		err = json.Unmarshal(data, &u)
		if err != nil {
			return err
		}
		s.log.Debugf("-------------- %+v", u)
		// u.Permission = ""

		p, ok := permissions[u.Permissions]
		if !ok {
			// WARN that didn't find a permission for this user.
			// so using the default permissions instead.
			continue
		}

		user := &ExpandedUser{
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
		users = append(users, user)
	}
	s.log.Debugf("permissions: %+v", permissions)
	s.log.Debugf("users: %+v", users)

	ac := &AuthConfig{
		Users: users,
	}
	conf, err := json.Marshal(ac)
	if err != nil {
		return err
	}
	s.log.Tracef("CONFIG: %s", string(conf))
	err = s.storeSnapshot(name, conf)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) storeSnapshot(name string, payload []byte) error {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))
	return ioutil.WriteFile(path, payload, 0666)
}

func (s *Server) storeConfig(data []byte) error {
	path := filepath.Join(s.currentConfigDir(), "auth.json")
	return ioutil.WriteFile(path, data, 0666)
}
