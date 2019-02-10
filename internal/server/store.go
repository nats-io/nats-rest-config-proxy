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
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nats-acl-config-proxy/api"
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

// getPermissions returns a set of permissions.
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

func (s *Server) deletePermissionResource(name string) error {
	path := filepath.Join(s.resourcesDir(), "permissions", fmt.Sprintf("%s.json", name))

	// If already gone then no need to delete...
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		return nil
	}

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

	// If already gone then no need to delete...
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		return nil
	}

	return os.Remove(path)
}

// getConfigSnapshot
func (s *Server) getConfigSnapshot(name string) ([]byte, error) {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))
	return ioutil.ReadFile(path)
}

func (s *Server) deleteConfigSnapshot(name string) error {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))

	// If already gone then no need to delete...
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		return nil
	}

	return os.Remove(path)
}

// buildConfigSnapshot will create the configuration with the users and permission.
func (s *Server) buildConfigSnapshot(name string) error {
	permissions, err := s.getPermissions()
	if err != nil {
		return err
	}

	users := make([]*api.ConfigUser, 0)
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
			s.log.Tracef("User %q will use default permissions", u.Username)
			continue
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
		users = append(users, user)
	}

	ac := &api.AuthConfig{
		Users: users,
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

func (s *Server) storeSnapshot(name string, payload []byte) error {
	path := filepath.Join(s.snapshotsDir(), fmt.Sprintf("%s.json", name))
	return ioutil.WriteFile(path, payload, 0666)
}

func (s *Server) storeConfig(data []byte) error {
	path := filepath.Join(s.currentConfigDir(), "auth.json")
	return ioutil.WriteFile(path, data, 0666)
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
	return nil
}
