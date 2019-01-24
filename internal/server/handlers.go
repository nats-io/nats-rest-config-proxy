// Copyright 2018 The NATS Authors
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
	"net/http"
	"strings"
	"time"
)

func (s *Server) HandleAccounts(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	fmt.Fprintf(w, "Accounts\n")
}

func (s *Server) HandleAccount(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	name := strings.TrimPrefix(r.URL.Path, "/v1/auth/accounts/")
	fmt.Fprintf(w, "Account: %s\n", name)
}

func (s *Server) HandleIdents(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	fmt.Fprintf(w, "Idents \n")
}

func (s *Server) HandleIdent(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	name := strings.TrimPrefix(r.URL.Path, "/v1/auth/idents/")
	fmt.Fprintf(w, "Idents: %s\n", name)
}

func (s *Server) HandlePerms(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	fmt.Fprintf(w, "Perms \n")
}

func (s *Server) HandlePerm(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	name := strings.TrimPrefix(r.URL.Path, "/v1/auth/perms/")
	fmt.Fprintf(w, "Perm: %s\n", name)
}

func (s *Server) HandleSnapshot(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	fmt.Fprintf(w, "Snapshot \n")
}

func (s *Server) HandlePublish(w http.ResponseWriter, r *http.Request) {
	defer s.traceRequest(r, time.Now())
	fmt.Fprintf(w, "Publish \n")
}
