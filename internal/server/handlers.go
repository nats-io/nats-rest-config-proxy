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
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// HandlePerm
func (s *Server) HandlePerm(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.traceRequest(req, size, status, time.Now())
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

		// Store permission
		s.log.Tracef("Permission %q: %s", name, string(payload))
		err = s.storePermissionResource(name, payload)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprintf(w, "Perm: %s\n", name)
	case "GET":
		s.log.Debugf("Retrieving permission resource %q", name)
		var resource []byte
		resource, err = s.getPermissionResource(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprint(w, string(resource))
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
		s.traceRequest(req, size, status, time.Now())
	}()
	name := strings.TrimPrefix(req.URL.Path, "/v1/auth/idents/")

	// PUT
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

		var resource []byte
		resource, err = s.getUserResource(name)
		if err != nil {
			status = http.StatusInternalServerError
			return
		}
		fmt.Fprint(w, string(resource))
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
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
		s.traceRequest(req, size, status, time.Now())
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
	var (
		size   int
		status int = http.StatusOK
		err    error
	)
	defer func() {
		s.processErr(err, status, w, req)
		s.traceRequest(req, size, status, time.Now())
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
		fmt.Fprintf(w, "Configuration published\n")
	default:
		status = http.StatusMethodNotAllowed
		err = fmt.Errorf("%s is not allowed on %q", req.Method, req.URL.Path)
	}
}

// HandlePerms
func (s *Server) HandlePerms(w http.ResponseWriter, r *http.Request) {
	// defer s.traceRequest(r, time.Now())
	fmt.Fprintf(w, "Perms \n")
}

// HandleIdents
func (s *Server) HandleIdents(w http.ResponseWriter, r *http.Request) {
	// defer s.traceRequest(r, time.Now())
	fmt.Fprintf(w, "Idents \n")
}

// HandleHealthz handles healthz.
func (s *Server) HandleHealthz(w http.ResponseWriter, req *http.Request) {
	var (
		size   int
		status int = http.StatusOK
	)
	defer s.traceRequest(req, size, status, time.Now())
	fmt.Fprintf(w, "OK\n")
}

func (s *Server) processErr(err error, status int, w http.ResponseWriter, req *http.Request) {
	if err != nil {
		errMsg := fmt.Sprintf("Error: %s", err)
		s.log.Errorf(errMsg)
		http.Error(w, errMsg, status)
	}
}
