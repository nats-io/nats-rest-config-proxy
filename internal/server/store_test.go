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

func TestMergeDuplicateUsers(t *testing.T) {
	permA := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"a"},
		},
	}
	permB := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"b"},
		},
	}
	permAB := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"a", "b"},
		},
	}

	permC := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"a"},
			Deny:  []string{"aa"},
		},
	}
	permD := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"b"},
		},
	}
	permCD := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"a", "b"},
			Deny:  []string{"aa"},
		},
	}

	cases := []struct {
		name  string
		users []*api.ConfigUser
		want  []*api.ConfigUser
	}{
		{
			name: "different usernames no-op",
			users: []*api.ConfigUser{
				{Username: "foo", Permissions: permA},
				{Username: "bar", Permissions: permA},
			},
			want: []*api.ConfigUser{
				{Username: "foo", Permissions: permA},
				{Username: "bar", Permissions: permA},
			},
		},
		{
			name: "different creds no-op",
			users: []*api.ConfigUser{
				{Username: "foo", Password: "fizz", Permissions: permA},
				{Username: "foo", Password: "buzz", Permissions: permA},
			},
			want: []*api.ConfigUser{
				{Username: "foo", Password: "fizz", Permissions: permA},
				{Username: "foo", Password: "buzz", Permissions: permA},
			},
		},
		{
			name: "merge perm a",
			users: []*api.ConfigUser{
				{Username: "foo", Permissions: permA},
				{Username: "foo", Permissions: permA},
			},
			want: []*api.ConfigUser{
				{Username: "foo", Permissions: permA},
			},
		},
		{
			name: "merge perm a and b",
			users: []*api.ConfigUser{
				{Username: "foo", Permissions: permA},
				{Username: "foo", Permissions: permB},
			},
			want: []*api.ConfigUser{
				{Username: "foo", Permissions: permAB},
			},
		},
		{
			name: "merge perm c and d",
			users: []*api.ConfigUser{
				{Username: "foo", Permissions: permC},
				{Username: "foo", Permissions: permD},
			},
			want: []*api.ConfigUser{
				{Username: "foo", Permissions: permCD},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergeDuplicateUsers(c.users)
			if !configUsersEqual(got, c.want) {
				t.Errorf("Expected len %d, got len: %d", len(c.want), len(got))
				t.Errorf("Expected %#v, got: %#v", c.want, got)
				t.Error("--- got ---")
				for i, u := range got {
					t.Errorf("%d Username: %#v\n", i, u.Username)
					t.Errorf("%d Password: %#v\n", i, u.Password)
					t.Errorf("%d Nkey: %#v\n", i, u.Nkey)
					t.Errorf("%d Permissions: %#v\n", i, u.Permissions)
					t.Errorf("%d Publish: %#v\n", i, u.Permissions.Publish)
					t.Errorf("%d Subscribe: %#v\n", i, u.Permissions.Subscribe)
				}
			}
		})
	}
}

func TestMergeDuplicateUsersMixedPermissions(t *testing.T) {
	permA := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"a"},
		},
	}
	permB := &api.Permissions{
		Subscribe: &api.PermissionRules{
			Allow: []string{"b"},
		},
	}
	permAB := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"a"},
		},
		Subscribe: &api.PermissionRules{
			Allow: []string{"b"},
		},
	}

	cases := []struct {
		name  string
		users []*api.ConfigUser
		want  []*api.ConfigUser
	}{
		{
			name: "merge perm a and b",
			users: []*api.ConfigUser{
				{Username: "foo", Permissions: permA},
				{Username: "foo", Permissions: permB},
			},
			want: []*api.ConfigUser{
				{Username: "foo", Permissions: permAB},
			},
		},
		{
			name: "merge perm b and a",
			users: []*api.ConfigUser{
				{Username: "foo", Permissions: permB},
				{Username: "foo", Permissions: permA},
			},
			want: []*api.ConfigUser{
				{Username: "foo", Permissions: permAB},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergeDuplicateUsers(c.users)
			if !configUsersEqual(got, c.want) {
				t.Errorf("Expected len %d, got len: %d", len(c.want), len(got))
				t.Errorf("Expected %#v, got: %#v", c.want, got)
				t.Error("--- got ---")
				for i, u := range got {
					t.Errorf("%d Username: %#v\n", i, u.Username)
					t.Errorf("%d Password: %#v\n", i, u.Password)
					t.Errorf("%d Nkey: %#v\n", i, u.Nkey)
					t.Errorf("%d Permissions: %#v\n", i, u.Permissions)
					t.Errorf("%d Publish: %#v\n", i, u.Permissions.Publish)
					t.Errorf("%d Subscribe: %#v\n", i, u.Permissions.Subscribe)
				}
			}
		})
	}
}

func configUsersEqual(a, b []*api.ConfigUser) bool {
	if len(a) != len(b) {
		return false
	}

	var found bool
	for _, ua := range a {
		found = false
		for _, ub := range b {
			if reflect.DeepEqual(ua, ub) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
