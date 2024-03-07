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

// User represents the payload that a client can make.
type User struct {
	// Username
	Username string `json:"username,omitempty"`

	// Password
	Password string `json:"password,omitempty"`

	// Nkey
	Nkey string `json:"nkey,omitempty"`

	// FIXME: Change into role and consolidate into a single type?
	// it would have to be filtered out on export though since
	// cannot have an extra field that is not recognized by the
	// server.
	Permissions string `json:"permissions,omitempty"`

	// Account is the account on which this user exists,
	// by default being the global account.
	Account string `json:"account,omitempty"`
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
	// Publish are the publish permissions.
	Publish *PermissionRules `json:"publish,omitempty"`

	// Subscribe are the subscriber permissions.
	Subscribe *PermissionRules `json:"subscribe,omitempty"`

	// Responses are response rules permissions.
	Responses *ResponseRules `json:"allow_responses,omitempty"`
}

// AsJSON returns a byte slice of the type.
func (p *Permissions) AsJSON() ([]byte, error) {
	return marshalIndent(p)
}

// PermissionRules represents the allow/deny rules for
// publish/subscribe.
type PermissionRules struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// ResponseRules represents the reponse permissions.
type ResponseRules struct {
	Max     int    `json:"max,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// ConfigUser is a user as it will be represented in the
// configuration of the NATS Server.
type ConfigUser struct {
	Username    string       `json:"username,omitempty"`
	Password    string       `json:"password,omitempty"`
	Nkey        string       `json:"nkey,omitempty"`
	Permissions *Permissions `json:"permissions,omitempty"`
}

// Subject mapping destination is for mapping subjects globally, by account, or
// by import.
type SubjectMap struct {
	Destination string `json:"destination,omitempty"`
	Weight      string `json:"weight,omitempty"`
	Cluster     string `json:"cluster,omitempty"`
}

// Account with users.
type Account struct {
	// Users that belong to the account.
	Users []*ConfigUser `json:"users,omitempty"`

	// Exports are the exports from this account.
	Exports []*Export `json:"exports,omitempty"`

	// Imports are the imports from this account.
	Imports []*Import `json:"imports,omitempty"`

	// JetStream enables the JS config.
	JetStream *AccountJetStreamConfig `json:"jetstream,omitempty"`

	// Subject mapping enables remapping subject and partitions
	Mappings map[string][]*SubjectMap `json:"mappings,omitempty"`

	// MessageTracing enables path tracing using otel headers
	MessageTracing *AccountMsgTrace `json:"msg_trace,omitempty"`
}

// AsJSON returns a byte slice of the type.
func (u *Account) AsJSON() ([]byte, error) {
	return marshalIndent(u)
}

// Export
type Export struct {
	Stream     string   `json:"stream,omitempty"`
	Service    string   `json:"service,omitempty"`
	Accounts   []string `json:"accounts,omitempty"`
	Response   string   `json:"response,omitempty"`
	AllowTrace bool     `json:"allow_trace,omitempty"`
}

// Import
type Import struct {
	Service      *GenericImport `json:"service,omitempty"`
	Stream       *StreamImport  `json:"stream,omitempty"`
	StreamPrefix string         `json:"prefix,omitempty"`
	ServiceTo    string         `json:"to,omitempty"`
}

// AccountJetStream maps to the NATS Config.
type AccountJetStream struct {
	MaxMemoryStore *int64 `json:"max_mem,omitempty"`
	MaxFileStore   *int64 `json:"max_file,omitempty"`
	MaxStreams     *int64 `json:"max_streams,omitempty"`
	MaxConsumers   *int64 `json:"max_consumers,omitempty"`
}

type AccountJetStreamConfig struct {
	Enabled          bool `json:"enabled,omitempty"`
	AccountJetStream `json:",inline"`
}

type AccountMsgTrace struct {
	DestinationSubject string `json:"dest"`
	SamplingPct        int    `json:"sampling"`
}

type GlobalJetStream struct {
	StoreDir         string `json:"store_dir,omitempty"`
	AccountJetStream `json:",inline"`
}

type StreamImport struct {
	GenericImport
	AllowTrace bool `json:"allow_trace,omitempty"`
}

// GenericImport are common fields shared between stream and service imports
type GenericImport struct {
	Account string `json:"account,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// AuthConfig represents the complete authorization config
// for the NATS Server.
type AuthConfig struct {
	// Users that belong to the global account.
	Users []*ConfigUser `json:"users"`

	// Accounts that separate the subject namespaces.
	Accounts map[string]*Account `json:"accounts,omitempty"`
}

// AsJSON returns the JSON representation of the AuthConfig.
func (ac *AuthConfig) AsJSON() ([]byte, error) {
	return marshalIndent(ac)
}
