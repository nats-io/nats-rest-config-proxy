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
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/nats-io/nats-rest-config-proxy/api"
)

func TestStoreGetPermission(t *testing.T) {
	dir, err := ioutil.TempDir("", "acl-proxy-data-dir-")
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{opts: &Options{DataDir: dir}}
	err = s.setupStoreDirectories()
	if err != nil {
		t.Fatal(err)
	}

	expected := &api.Permissions{}
	err = s.storePermissionResource("foo", expected)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.getPermissionResource("foo")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("Expected %+v, got: %+v", expected, got)
	}
}

func TestStoreGetUser(t *testing.T) {
	dir, err := ioutil.TempDir("", "acl-proxy-data-dir-")
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{opts: &Options{DataDir: dir}}
	err = s.setupStoreDirectories()
	if err != nil {
		t.Fatal(err)
	}

	expected := &api.User{}
	err = s.storeUserResource("foo", expected)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.getUserResource("foo")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("Expected %+v, got: %+v", expected, got)
	}
}
