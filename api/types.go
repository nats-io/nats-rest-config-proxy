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

package api

import (
	"bytes"
	"encoding/json"
)

// User represents the payload that a client can make
type User struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Nkey     string `json:"nkey,omitempty"`

	// FIXME: Change into role and consolidate into a single type?
	// it would have to be filtered out on export though since
	// cannot have an extra field that is not recognized by the
	// server.
	Permissions string `json:"permissions,omitempty"`
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

// AsJSON returns a byte slice of the type.
func (u *User) AsJSON() ([]byte, error) {
	return marshalIndent(u)
}

// Permissions are the publish/subscribe rules.
type Permissions struct {
	Publish   *PermissionRules `json:"publish,omitempty"`
	Subscribe *PermissionRules `json:"subscribe,omitempty"`
}

// AsJSON returns a byte slice of the type.
func (p *Permissions) AsJSON() ([]byte, error) {
	return marshalIndent(p)
}

// PermissionRules represents the allow/deny rules for publish/subscribe.
type PermissionRules struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// ConfigUser is a user as it will be represented in the
// configuration of the NATS Server.
type ConfigUser struct {
	Username    string       `json:"username,omitempty"`
	Password    string       `json:"password,omitempty"`
	Nkey        string       `json:"nkey,omitempty"`
	Permissions *Permissions `json:"permissions,omitempty"`
}

// AuthConfig represents the complete authorization config
// for the NATS Server.
type AuthConfig struct {
	Users []*ConfigUser `json:"users"`
}

func (ac *AuthConfig) AsJSON() ([]byte, error) {
	return marshalIndent(ac)
}
