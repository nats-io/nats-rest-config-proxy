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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats-acl-config-proxy/api"
)

// HandlePerm handles a request to create/update permissions.
func (s *Server) HandlePerm(w http.ResponseWriter, req *http.Request) {
	if err, status := s.authHandler(req); err != nil {
		s.log.Errorf(err.Error())
		http.Error(w, err.Error(), status)
		return
	}

	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()
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
		s.log.Tracef("Permission %q: %s", name, string(payload))

		// Should get a type here instead
		err = s.storePermissionResource(name, payload)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "Perm: %s\n", name)
	case "GET":
		s.log.Debugf("Retrieving permission resource %q", name)
		resource, err := s.getPermissionResource(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		payload, err := resource.AsJSON()
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

		err = s.deletePermissionResource(name)
		if err != nil {
			status = http.StatusInternalServerError
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
	if err, status := s.authHandler(req); err != nil {
		s.log.Errorf(err.Error())
		http.Error(w, err.Error(), status)
		return
	}

	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()
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

		// Store permission
		s.log.Tracef("User %q: %v", name, string(payload))
		err = s.storeUserResource(name, payload)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "User %q updated\n", name)
	case "GET":
		s.log.Debugf("Retrieving user resource %q", name)

		var resource *api.User
		resource, err = s.getUserResource(name)
		if err != nil {
			status = http.StatusInternalServerError
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
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "Deleted user resource %q", name)
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandleSnapshot
func (s *Server) HandleSnapshot(w http.ResponseWriter, req *http.Request) {
	if err, status := s.authHandler(req); err != nil {
		s.log.Errorf(err.Error())
		http.Error(w, err.Error(), status)
		return
	}

	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

	// PUT
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
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandlePublish
func (s *Server) HandlePublish(w http.ResponseWriter, req *http.Request) {
	if err, status := s.authHandler(req); err != nil {
		s.log.Errorf(err.Error())
		http.Error(w, err.Error(), status)
		return
	}

	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

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
	if err, status := s.authHandler(req); err != nil {
		s.log.Errorf(err.Error())
		http.Error(w, err.Error(), status)
		return
	}

	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

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
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
		return
	}
}

// HandleIdents
func (s *Server) HandleIdents(w http.ResponseWriter, req *http.Request) {
	if err, status := s.authHandler(req); err != nil {
		s.log.Errorf(err.Error())
		http.Error(w, err.Error(), status)
		return
	}

	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.log.traceRequest(req, size, status, time.Now())
	}()

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
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
		return
	}
}

// HandleHealthz handles healthz.
func (s *Server) HandleHealthz(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
	)
	defer s.log.traceRequest(req, size, status, time.Now())
	fmt.Fprintf(w, "OK\n")
}

func (s *Server) authHandler(req *http.Request) (error, int) {
	s.mu.Lock()
	user := s.opts.HTTPUser
	s.mu.Unlock()

	if user == "" {
		// Nothing else to do
		return nil, 0
	}

	auth := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if len(auth) != 2 || auth[0] != "Basic" {
		return errors.New("authorization failed"), http.StatusUnauthorized
	}
	payload, err := base64.StdEncoding.DecodeString(auth[1])
	if err != nil {
		return errors.New("authorization failed"), http.StatusBadRequest
	}
	pair := strings.SplitN(string(payload), ":", 2)

	if len(pair) != 2 || !s.isValidUserPass(pair[0], pair[1]) {
		return errors.New("authorization failed"), http.StatusUnauthorized
	}

	return nil, 0
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
