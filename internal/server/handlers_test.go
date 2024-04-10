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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-rest-config-proxy/api"
)

func createFixtures(t *testing.T, host string) {
	// Create permissions.
	payload := `{
         "publish": {
           "allow": ["foo.*", "bar.>"]
          },
          "subscribe": {
            "deny": ["quux"]
          }
        }`
	resp, _, err := curl("PUT", host+"/v1/auth/perms/normal-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload = `{
          "username": "first-user",
          "password": "secret",
          "permissions": "normal-user"
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/first-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	payload = `{
          "username": "second-user",
          "password": "secret",
          "permissions": "normal-user"
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/second-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	// Confirm request/response
	req, err := http.NewRequest("GET", "/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.HandleHealthz)
	handler.ServeHTTP(rr, req)
	if got := rr.Code; got != http.StatusOK {
		t.Errorf("Expected %v, got: %v", http.StatusOK, got)
	}
	expected := "OK\n"
	if rr.Body.String() != expected {
		t.Errorf("Expected: %v, got: %v",
			rr.Body.String(), expected)
	}
}

func TestIdentsHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)

	// Create a couple of users
	payload := `{
          "username": "sample-user",
          "password": "secret",
          "permissions": "normal-user"
        }`
	resp, _, err := curl("PUT", host+"/v1/auth/idents/sample-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	ur, err := s.getUserResource("sample-user")
	if err != nil {
		t.Fatal(err)
	}
	expected := &api.User{
		Username:    "sample-user",
		Password:    "secret",
		Permissions: "normal-user",
	}
	if !reflect.DeepEqual(expected, ur) {
		t.Errorf("Expected: %+v\nGot: %+v", expected, ur)
	}

	resp, _, err = curl("HEAD", host+"/v1/auth/idents/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 {
		t.Fatalf("Expected Method Not Allowed, got: %v", resp.StatusCode)
	}

	// Make sure duplicate usernames aren't allowed.
	payload = `{
          "username": "fizz",
          "password": "secret",
          "permissions": "normal-user"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/fizz", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	payload = `{
          "username": "fizz",
          "password": "secret",
          "permissions": "normal-user",
          "account": "account-fizz"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/buzz", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Fatalf("Expected Conflict, got: %v", resp.StatusCode)
	}
}

func TestPermsHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)

	// Create permissions.
	payload := `{
         "publish": {
           "allow": ["foo", "bar"]
          },
          "subscribe": {
            "deny": ["quux"]
          }
        }`
	resp, _, err := curl("PUT", host+"/v1/auth/perms/normal-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	ur, err := s.getPermissionResource("normal-user")
	if err != nil {
		t.Fatal(err)
	}
	expected := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{"foo", "bar"},
		},
		Subscribe: &api.PermissionRules{
			Deny: []string{"quux"},
		},
	}
	if !reflect.DeepEqual(expected, ur) {
		t.Errorf("Expected: %+v\nGot: %+v", expected, ur)
	}
}

func TestPublishHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	s.opts.PublishScript = filepath.Join(s.opts.DataDir, "publish.sh")

	script := `#!/bin/sh
echo 'Publishing script...' > ./artifact.log
`
	err = os.WriteFile(s.opts.PublishScript, []byte(script), 0755)
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	// Publish the config
	resp, _, err := curl("POST", host+"/v1/auth/publish", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	config, err := s.getCurrentConfig()
	if err != nil {
		t.Fatal(err)
	}
	expected := `{
  "users": [
    {
      "username": "first-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    },
    {
      "username": "second-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    }
  ]
}
`
	got := string(config)
	if expected != got {
		t.Fatalf("Expected: %s\n, got: %s", expected, got)
	}

	// Confirm that the publish script was executed
	result, err := os.ReadFile(filepath.Join(s.opts.DataDir, "artifact.log"))
	if err != nil {
		t.Fatal(err)
	}
	got = string(result)
	expected = "Publishing script...\n"
	if got != expected {
		t.Fatalf("Expected: %s, got: %s", expected, got)
	}
}

func TestPublishScriptFailure(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	s.opts.PublishScript = filepath.Join(s.opts.DataDir, "publish.sh")

	script := `#!/bin/sh
exit 1
`
	err = os.WriteFile(s.opts.PublishScript, []byte(script), 0755)
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	// Publish the config
	resp, _, err := curl("POST", host+"/v1/auth/publish", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected internal server error, got: %v", resp.StatusCode)
	}

	config, err := s.getCurrentConfig()
	if err != nil {
		t.Fatal(err)
	}
	expected := `{
  "users": [
    {
      "username": "first-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    },
    {
      "username": "second-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    }
  ]
}
`
	got := string(config)
	if expected != got {
		t.Fatalf("Expected: %s\n, got: %s", expected, got)
	}
}

func TestDeletePermissionsNameMissing(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, _, err := curl("DELETE", host+"/v1/auth/perms/", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected bad request, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("DELETE", host+"/v1/auth/perms/not-found", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("Expected bad request, got: %v", resp.StatusCode)
	}
}

func TestDeleteUsersNameMissing(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, _, err := curl("DELETE", host+"/v1/auth/idents/", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected bad request, got: %v", resp.StatusCode)
	}
}

func TestDeletePermissions(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, _, err := curl("DELETE", host+"/v1/auth/perms/normal-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("DELETE", host+"/v1/auth/idents/first-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("DELETE", host+"/v1/auth/idents/second-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v1/auth/publish", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	config, err := s.getCurrentConfig()
	if err != nil {
		t.Fatal(err)
	}
	expected := `{
  "users": []
}
`
	got := string(config)
	if expected != got {
		t.Fatalf("Expected: %s\n, got: %s", expected, got)
	}
}

func TestDeleteAllUsers(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, _, err := curl("DELETE", host+"/v1/auth/idents", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v1/auth/publish", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	config, err := s.getCurrentConfig()
	if err != nil {
		t.Fatal(err)
	}
	expected := `{
  "users": []
}
`
	got := string(config)
	if expected != got {
		t.Fatalf("Expected: %s\n, got: %s", expected, got)
	}
}

func TestDeleteAllPermissions(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, body, err := curl("DELETE", host+"/v1/auth/perms", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	got := string(body)
	expected := `User "first-user" is using permission "normal-user"`
	if !strings.Contains(got, expected) {
		t.Errorf("Expected: %v, got: %v", expected, got)
	}

	resp, _, err = curl("DELETE", host+"/v1/auth/idents/first-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("DELETE", host+"/v1/auth/idents/second-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Should be able to delete all permissions now
	resp, _, err = curl("DELETE", host+"/v1/auth/perms", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, data, err := curl("GET", host+"/v1/auth/perms", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	var p map[string]*api.Permissions
	err = json.Unmarshal(data, &p)
	if err != nil {
		t.Fatal(err)
	}
	found := len(p)
	if found > 0 {
		t.Fatalf("Expected no permissions, found: %v", found)
	}
}

func TestPermsList(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	payload := `{
          "publish":   { "allow": ["hello", "world"] },
          "subscribe": { "allow": ["public.>"], "deny": ["private.>"] }
        }`
	resp, _, err := curl("PUT", host+"/v1/auth/perms/normal-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
          "publish":   { "allow": [">"] },
          "subscribe": { "allow": [">"] }
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/admin-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	var data []byte
	resp, data, err = curl("GET", host+"/v1/auth/perms", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	var perms map[string]*api.Permissions
	err = json.Unmarshal(data, &perms)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]*api.Permissions{
		"admin-user": &api.Permissions{
			Publish: &api.PermissionRules{
				Allow: []string{">"},
			},
			Subscribe: &api.PermissionRules{
				Allow: []string{">"},
			},
		},
		"normal-user": &api.Permissions{
			Publish: &api.PermissionRules{
				Allow: []string{"hello", "world"},
			},
			Subscribe: &api.PermissionRules{
				Allow: []string{"public.>"},
				Deny:  []string{"private.>"},
			},
		},
	}
	if !reflect.DeepEqual(expected, perms) {
		t.Errorf("Expected: %+v\nGot: %+v", expected, perms)
	}
}

func TestUsersList(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	var data []byte
	resp, data, err := curl("GET", host+"/v1/auth/idents", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	var users []*api.User
	err = json.Unmarshal(data, &users)
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]*api.User, 0)
	firstUser := &api.User{
		Username:    "first-user",
		Password:    "secret",
		Permissions: "normal-user",
	}
	secondUser := &api.User{
		Username:    "second-user",
		Password:    "secret",
		Permissions: "normal-user",
	}
	expected = append(expected, firstUser, secondUser)
	if !reflect.DeepEqual(expected, users) {
		t.Errorf("Expected: %+v\nGot: %+v", expected, users)
	}
}

func TestGetUser(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	var data []byte
	resp, data, err := curl("GET", host+"/v1/auth/idents/first-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	var user *api.User
	err = json.Unmarshal(data, &user)
	if err != nil {
		t.Fatal(err)
	}
	expected := &api.User{
		Username:    "first-user",
		Password:    "secret",
		Permissions: "normal-user",
	}
	if !reflect.DeepEqual(expected, user) {
		t.Errorf("Expected: %+v\nGot: %+v", expected, user)
	}
}

func TestGetSinglePermission(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	payload := `{
          "publish":   { "allow": ["hello", "world"] },
          "subscribe": { "allow": ["public.>"], "deny": ["private.>"] }
        }`
	resp, _, err := curl("PUT", host+"/v1/auth/perms/normal-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
          "publish":   { "allow": [">"] },
          "subscribe": { "allow": [">"] }
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/admin-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	var data []byte
	resp, data, err = curl("GET", host+"/v1/auth/perms/admin-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	var permission *api.Permissions
	err = json.Unmarshal(data, &permission)
	if err != nil {
		t.Fatal(err)
	}
	expected := &api.Permissions{
		Publish: &api.PermissionRules{
			Allow: []string{">"},
		},
		Subscribe: &api.PermissionRules{
			Allow: []string{">"},
		},
	}
	if !reflect.DeepEqual(expected, permission) {
		t.Errorf("Expected: %+v\nGot: %+v", expected, permission)
	}
}

func TestSnapshotHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, _, err := curl("HEAD", host+"/v1/auth/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 {
		t.Fatalf("Expected Method Not Allowed, got: %v", resp.StatusCode)
	}

	// Publish the snapshot
	resp, _, err = curl("POST", host+"/v1/auth/snapshot", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	config, err := s.getConfigSnapshot("latest")
	if err != nil {
		t.Fatal(err)
	}
	expected := `{
  "users": [
    {
      "username": "first-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    },
    {
      "username": "second-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    }
  ]
}
`
	got := string(config)
	if expected != got {
		t.Fatalf("Expected: %s\n, got: %s", expected, got)
	}
}

func TestValidateSnapshotHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)

	// Create permissions.
	payload := `{
         "publish": {
           "allow": ["foo.*", "bar.>"]
          },
          "subscribe": {
            "deny": ["quux"]
          }
        }`
	resp, out, err := curl("PUT", host+"/v1/auth/perms/normal-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create account
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/foo", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Should prevent creating invalid accounts
	payload2 := `{
         "publish": {
           "allow": ["foo.bar.*"]
          }
        }`
	badName := "foo.bar.quux"
	resp, _, err = curlRawEndpoint("PUT", host, "/v1/auth/accounts/"+badName, []byte(payload2))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected bad request, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload = `{
          "username": "first-user",
          "password": "secret",
          "permissions": "normal-user",
          "account": "foo"
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/first-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	payload = `{
          "username": "second-user",
          "password": "secret",
          "permissions": "normal-user",
          "account": "foo"
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/second-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish the snapshot
	resp, out, err = curl("POST", host+"/v2/auth/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create invalid permissions, using empty string in this case.
	payload = `{
         "publish": {
           "allow": [""]
          },
          "subscribe": {
            "deny": ["foo"]
          }
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/bad-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create bad fixture
	payload = `{
          "username": "third-user",
          "password": "secret",
          "permissions": "bad-user",
          "account": "foo"
        }`
	resp, out, err = curl("PUT", host+"/v1/auth/idents/third-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Validate should fail
	resp, out, err = curl("POST", host+"/v2/auth/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected 500, got: %v", resp.StatusCode)
	}

	result := string(out)
	if !strings.Contains(result, `subject "" is not a valid subject`) {
		t.Fatal("Expected to find invalidation error")
	}
}

func TestValidateSnapshotWithoutAccounts(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)

	// Create permissions.
	payload := `{
         "publish": {
           "allow": ["foo.*", "bar.>"]
          },
          "subscribe": {
            "deny": ["quux"]
          }
        }`
	resp, out, err := curl("PUT", host+"/v1/auth/perms/normal-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload = `{
          "username": "first-user",
          "password": "secret",
          "permissions": "normal-user",
          "account": "foo"
        }`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/first-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected error, got: %v", resp.StatusCode)
	}

	// Publish the snapshot and validate which should fail
	resp, out, err = curl("POST", host+"/v2/auth/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	expected := "Error: account foo does not exist!\n"
	if got != expected {
		t.Fatalf("Expected %v, got: %v", expected, got)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected server error, got: %v", resp.StatusCode)
	}
}

func TestSnapshotWithNameHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	// Publish the snapshot
	resp, _, err := curl("POST", host+"/v1/auth/snapshot?name=sample", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	config, err := s.getConfigSnapshot("sample")
	if err != nil {
		t.Fatal(err)
	}
	expected := `{
  "users": [
    {
      "username": "first-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    },
    {
      "username": "second-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    }
  ]
}
`
	got := string(config)
	if expected != got {
		t.Fatalf("Expected: %s\n, got: %s", expected, got)
	}
}

func TestSnapshotWithNameDelete(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	// Publish the snapshot
	resp, _, err := curl("POST", host+"/v1/auth/snapshot?name=foo", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Delete the snapshot
	resp, _, err = curl("DELETE", host+"/v1/auth/snapshot?name=foo", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Delete non existant snapshot
	resp2, _, err := curl("DELETE", host+"/v1/auth/snapshot?name=foo", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != 404 {
		t.Fatalf("Expected 404, got: %v", resp.StatusCode)
	}
}

func TestDeleteUser(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, _, err := curl("DELETE", host+"/v1/auth/idents/first-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("GET", host+"/v1/auth/idents/first-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("DELETE", host+"/v1/auth/idents/first-user", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
}

func TestVerifyAuthFails(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	s.opts.CertFile = "./../../test/certs/server.pem"
	s.opts.KeyFile = "./../../test/certs/server-key.pem"
	s.opts.CaFile = "./../../test/certs/ca.pem"
	config, err := s.generateTLSConfig()
	if err != nil {
		t.Fatalf("Unexpected error when generating config: %s", err)
	}

	// Confirm request/response
	certs := make([]*x509.Certificate, 0)
	certs = append(certs, config.Certificates[0].Leaf)

	// Test all the routes
	routes := []struct {
		method   string
		endpoint string
		status   int
		handler  http.HandlerFunc
	}{
		{"GET", "/v1/auth/perms/foo", 401, s.HandlePerm},
		{"GET", "/v1/auth/idents/foo", 401, s.HandlePerm},
		{"GET", "/v1/auth/perms", 401, s.HandlePerms},
		{"GET", "/v1/auth/perms/", 401, s.HandlePerm},
		{"GET", "/v1/auth/snapshot", 401, s.HandleSnapshot},
		{"GET", "/v1/auth/snapshot/", 401, s.HandleSnapshot},
		{"GET", "/v1/auth/publish/", 401, s.HandlePublish},
		{"GET", "/v1/auth/publish", 401, s.HandlePublish},
	}
	for _, route := range routes {
		t.Run(route.method+route.endpoint, func(t *testing.T) {
			req, err := http.NewRequest(route.method, route.endpoint, nil)
			if err != nil {
				t.Error(err)
			}
			req.TLS = &tls.ConnectionState{
				PeerCertificates: certs,
			}
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(route.handler)
			handler.ServeHTTP(rr, req)

			expected := route.status
			if got := rr.Code; got != expected {
				t.Errorf("Expected %v, got: %v", expected, got)
			}
		})
	}
}

func TestVerifyAuthWorks(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	s.opts.CertFile = "./../../test/certs/acme-client.pem"
	s.opts.KeyFile = "./../../test/certs/acme-client-key.pem"
	s.opts.CaFile = "./../../test/certs/ca.pem"
	s.opts.HTTPUsers = []string{"CN=acme.example.com,OU=ACME"}
	config, err := s.generateTLSConfig()
	if err != nil {
		t.Fatalf("Unexpected error when generating config: %s", err)
	}

	// Confirm request/response
	certs := make([]*x509.Certificate, 0)
	certs = append(certs, config.Certificates[0].Leaf)

	// Test all the routes
	routes := []struct {
		method   string
		endpoint string
		status   int
		handler  http.HandlerFunc
	}{
		{"GET", "/v1/auth/perms/foo", 500, s.HandlePerm},
		{"GET", "/v1/auth/idents/foo", 500, s.HandlePerm},
		{"GET", "/v1/auth/perms", 200, s.HandlePerms},
		{"GET", "/v1/auth/perms/", 500, s.HandlePerm},
		{"GET", "/v1/auth/snapshot", 404, s.HandleSnapshot},
		{"GET", "/v1/auth/snapshot/", 404, s.HandleSnapshot},
		{"GET", "/v1/auth/publish/", 405, s.HandlePublish},
		{"GET", "/v1/auth/publish", 405, s.HandlePublish},
	}
	for _, route := range routes {
		t.Run(route.method+route.endpoint, func(t *testing.T) {
			req, err := http.NewRequest(route.method, route.endpoint, nil)
			if err != nil {
				t.Error(err)
			}
			req.TLS = &tls.ConnectionState{
				PeerCertificates: certs,
			}
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(route.handler)
			handler.ServeHTTP(rr, req)

			expected := route.status
			if got := rr.Code; got != expected {
				t.Errorf("Expected %v, got: %v", expected, got)
			}
		})
	}
}

func TestAccountsHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	// The order in the following tests is important since there
	// is state dependent from each other.
	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	for _, test := range []struct {
		name     string
		account  string
		payload  string
		expected *api.Account
		err      error
	}{
		{
			"create foo account with exports",
			"foo",
			`{
                           "exports": [
                             { "stream": "foo.public.>" },
                             { "service": "foo.api" }
                           ]
                        }`,
			&api.Account{
				Exports: []*api.Export{
					{
						Stream: "foo.public.>",
					},
					{
						Service: "foo.api",
					},
				},
			},
			nil,
		},
		{
			"create bar account with limited scope export",
			"bar",
			`{
                           "exports": [
                             { "stream": "bar.public.>", "accounts": ["foo"] }
                           ]
                        }`,
			&api.Account{
				Exports: []*api.Export{
					{
						Stream:   "bar.public.>",
						Accounts: []string{"foo"},
					},
				},
			},
			nil,
		},
		{
			"create account with limited scope export that does not exist should fail",
			"fail",
			`{
                           "exports": [
                             { "stream": "quux.public.>", "accounts": ["none"] }
                           ]
                        }`,
			nil,
			errors.New(`Error: Account "none" defined in export does not exist`),
		},
		{
			"create quux account with stream import for foo which is public",
			"quux",
			`{
                           "imports": [
                             { "stream": {"account": "foo", "subject": "foo.public.>" } }
                           ]
                        }`,
			&api.Account{
				Imports: []*api.Import{
					{
						Stream: &api.StreamImport{
							GenericImport: api.GenericImport{
								Account: "foo",
								Subject: "foo.public.>",
							},
						},
					},
				},
			},
			nil,
		},
		{
			"create quuz account with service imports for foo which is public",
			"quuz",
			`{
                           "imports": [
                             { "service": {"account": "foo", "subject": "foo.api" } }
                           ]
                        }`,
			&api.Account{
				Imports: []*api.Import{
					{
						Service: &api.GenericImport{
							Account: "foo",
							Subject: "foo.api",
						},
					},
				},
			},
			nil,
		},
		{
			"create account with service imports for account that does not exist",
			"fail",
			`{
                           "imports": [
                             { "service": {"account": "none", "subject": "foo.api" } }
                           ]
                        }`,
			nil,
			errors.New(`Error: Account "none" defined in export does not exist`),
		},
		{
			"create fail account with stream imports for account that does not exist",
			"fail",
			`{
                           "imports": [
                             { "stream": {"account": "none", "subject": "foo.api" } }
                           ]
                        }`,
			nil,
			errors.New(`Error: Account "none" defined in export does not exist`),
		},
		{
			"create sample account with exports using wildcards",
			"sample",
			`{
                           "exports": [
                             { "service": "foo.api.>" },
                             { "service": "foo.*" }
                           ]
                        }`,
			&api.Account{
				Exports: []*api.Export{
					{
						Service: "foo.api.>",
					},
					{
						Service: "foo.*",
					},
				},
			},
			nil,
		},
		{
			"create sample account with imports using wildcards",
			"sample2",
			`{
                           "imports": [
                             { "service": { "account": "sample", "subject": "foo.api.>" } }
                           ]
                        }`,
			nil,
			errors.New("Error: Import service subject must not have a wildcard"),
		},
		{
			"create acctmap account with subject mapping",
			"acctmap",
			`{
				"mappings": {
				 "s1": [
				  {
				   "destination": "d1.1",
				   "weight": "50%",
				   "cluster": "foo"
				  },
				  {
				   "destination": "d1.2",
				   "weight": "50%"
				  }
				 ],
				 "s2": [
				  {
				   "destination": "d2.1",
				   "weight": "75%"
				  },
				  {
				   "destination": "d2.2",
				   "weight": "25%"
				  }
				 ]
				}
			   }`,
			&api.Account{
				Mappings: map[string][]*api.SubjectMap{
					"s1": {{Destination: "d1.1", Weight: "50%", Cluster: "foo"}, {Destination: "d1.2", Weight: "50%"}},
					"s2": {{Destination: "d2.1", Weight: "75%"}, {Destination: "d2.2", Weight: "25%"}},
				},
			},
			nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resp, body, err := curl("PUT", host+"/v1/auth/accounts/"+test.account, []byte(test.payload))
			if err != nil {
				t.Fatal(err)
			}
			if test.err != nil {
				if resp.StatusCode == 200 {
					t.Fatalf("Expected error, got success")
				}
				got := string(body)
				expected := test.err.Error() + "\n"
				if got != expected {
					t.Errorf("\nExpected: %+v\n     Got: %+v", expected, got)
				}

				return
			}

			if resp.StatusCode != 200 {
				t.Fatalf("Expected OK, got: %v", resp.StatusCode)
			}
			acc, err := s.getAccountResource(test.account)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(test.expected, acc) {
				t.Errorf("Expected: %+v\nGot: %+v", test.expected, acc)
			}
		})
	}

	// Create a user in each of the accounts.
	t.Run("publishing with multiple users using v1 endpoint", func(t *testing.T) {
		accounts := []string{"foo", "bar", "quux", "quuz", ""}
		for _, acc := range accounts {
			var username string
			if acc == "" {
				username = "global-user"
			} else {
				username = fmt.Sprintf("%s-user", acc)
			}

			payload := `{
                          "username": "%s",
                          "password": "secret",
                          "account": "%s"
                        }`
			payload = fmt.Sprintf(payload, username, acc)

			endpoint := fmt.Sprintf("%s/v1/auth/idents/%s", host, username)
			resp, _, err := curl("PUT", endpoint, []byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("Expected OK, got: %v", resp.StatusCode)
			}
		}

		// Now publish with the v1 endpoint
		// Create a Snapshot
		resp, _, err := curl("POST", host+"/v1/auth/snapshot?name=v1", []byte(""))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		// Publish a named snapshot
		resp, _, err = curl("POST", host+"/v1/auth/publish?name=v1", []byte(""))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		// Confirm the result
		contents, err := os.ReadFile(s.opts.DataDir + "/current/auth.json")
		if err != nil {
			t.Fatal(err)
		}
		expected := `{
  "users": [
    {
      "username": "global-user",
      "password": "secret"
    }
  ],
  "accounts": {
    "bar": {
      "users": [
        {
          "username": "bar-user",
          "password": "secret"
        }
      ],
      "exports": [
        {
          "stream": "bar.public.>",
          "accounts": [
            "foo"
          ]
        }
      ]
    },
    "foo": {
      "users": [
        {
          "username": "foo-user",
          "password": "secret"
        }
      ],
      "exports": [
        {
          "stream": "foo.public.>"
        },
        {
          "service": "foo.api"
        }
      ]
    },
    "quux": {
      "users": [
        {
          "username": "quux-user",
          "password": "secret"
        }
      ],
      "imports": [
        {
          "stream": {
            "account": "foo",
            "subject": "foo.public.>"
          }
        }
      ]
    },
    "quuz": {
      "users": [
        {
          "username": "quuz-user",
          "password": "secret"
        }
      ],
      "imports": [
        {
          "service": {
            "account": "foo",
            "subject": "foo.api"
          }
        }
      ]
    }
  }
}
`
		got := string(contents)
		if got != expected {
			t.Errorf("Expected: %q\nGot: %q", expected, got)
		}
	})

	t.Run("get all accounts", func(t *testing.T) {
		resp, body, err := curl("GET", host+"/v1/auth/accounts/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		expected := 6
		var got []interface{}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}

		if len(got) != expected {
			t.Errorf("Expected: %+v\nGot: %+v", expected, len(got))
		}
	})

	t.Run("get one account", func(t *testing.T) {
		resp, _, err := curl("GET", host+"/v1/auth/accounts/bar", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		resp, _, err = curl("GET", host+"/v1/auth/accounts/notexist", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 404 {
			t.Errorf("Expected Not Found, got: %v", resp.StatusCode)
		}
	})

	// Publish and snapshot with the new structure
	resp, _, err := curl("POST", host+"/v2/auth/snapshot?name=new", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v2/auth/publish?name=new", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("DELETE", host+"/v2/auth/snapshot?name=new", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v2/auth/publish", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	// Can't delete account because users are using it.
	resp, _, err = curl("DELETE", host+"/v1/auth/accounts/bar", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Errorf("Expected Conflict, got: %v", resp.StatusCode)
	}

	// Delete all users.
	resp, _, err = curl("DELETE", host+"/v1/auth/idents", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	// Now we can delete the acocunt.
	resp, _, err = curl("DELETE", host+"/v1/auth/accounts/bar", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	// Method not allowed
	resp, _, err = curl("HEAD", host+"/v1/auth/accounts/bar", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 {
		t.Errorf("Expected Method Not Allowed, got: %v", resp.StatusCode)
	}
}

func TestPublishHandlerV2(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	s.opts.PublishScript = filepath.Join(s.opts.DataDir, "publish.sh")

	script := `#!/bin/sh
echo 'Publishing script...' > ./artifact2.log
`
	err = os.WriteFile(s.opts.PublishScript, []byte(script), 0755)
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	waitServerIsReady(t, ctx, s)

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	createFixtures(t, host)

	resp, rerr, err := curl("POST", host+"/v2/auth/publish?name=foo", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	got := string(rerr)
	expected := "Error: Snapshot named \"foo\" does not exist!\n"
	if got != expected {
		t.Fatalf("\nExpected: %v,\n     Got: %v", expected, got)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish the config
	resp, _, err = curl("POST", host+"/v2/auth/publish", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	result, err := os.ReadFile(filepath.Join(s.opts.DataDir, "current", "accounts", "global.json"))
	if err != nil {
		t.Fatal(err)
	}

	expected = `{
  "users": [
    {
      "username": "first-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    },
    {
      "username": "second-user",
      "password": "secret",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    }
  ]
}
`
	got = string(result)
	if got != expected {
		t.Errorf("Expected: %q\nGot: %q", expected, got)
	}

	// Confirm that the publish script was executed
	result, err = os.ReadFile(filepath.Join(s.opts.DataDir, "artifact2.log"))
	if err != nil {
		t.Fatal(err)
	}
	got = string(result)
	expected = "Publishing script...\n"
	if got != expected {
		t.Fatalf("Expected: %s, got: %s", expected, got)
	}
}

func TestVerifyIdent(t *testing.T) {
	cases := []struct {
		name    string
		users   []*api.User
		u       *api.User
		wantErr bool
	}{
		{
			name:    "same name, same account",
			users:   []*api.User{{Username: "foo", Account: "bar"}},
			u:       &api.User{Username: "foo", Account: "bar"},
			wantErr: false,
		},
		{
			name:    "same name, different account",
			users:   []*api.User{{Username: "foo", Account: "bar"}},
			u:       &api.User{Username: "foo", Account: "fizz"},
			wantErr: true,
		},
		{
			name:    "same name, different passwords",
			users:   []*api.User{{Username: "foo", Password: "bar"}},
			u:       &api.User{Username: "foo", Password: "fizz"},
			wantErr: false,
		},
		{
			name:    "same name, different creds",
			users:   []*api.User{{Username: "foo", Password: "bar"}},
			u:       &api.User{Username: "foo", Nkey: "fizz"},
			wantErr: false,
		},
		{
			name:    "different accounts, different nkeys",
			users:   []*api.User{{Account: "foo", Nkey: "fizz"}},
			u:       &api.User{Account: "bar", Nkey: "buzz"},
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifyIdent(c.users, c.u)

			gotErr := err != nil
			if gotErr && !c.wantErr {
				t.Error("unexpected error")
				t.Fatalf("got=%q; want=nil", err)
			} else if !gotErr && c.wantErr {
				t.Fatal("unexpected ok")
			}
		})
	}
}

func TestAccountsJetStreamHandler(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	intPtr := func(n int64) *int64 {
		return &n
	}

	// The order in the following tests is important since there
	// is state dependent from each other.
	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	for _, test := range []struct {
		name     string
		account  string
		payload  string
		expected *api.Account
		err      error
	}{
		{
			"create js1 account with jetstream using defaults",
			"js1",
			`{
                           "jetstream": {}
                        }`,
			&api.Account{
				JetStream: &api.AccountJetStreamConfig{},
			},
			nil,
		},
		{
			"create js2 account with jetstream using defaults with explicit enable",
			"js2",
			`{
                           "jetstream": {
                             "enabled": true
                           }
                        }`,
			&api.Account{
				JetStream: &api.AccountJetStreamConfig{
					Enabled: true,
				},
			},
			nil,
		},
		{
			"create js3 account with jetstream and explicit limits",
			"js3",
			`{
                           "jetstream": {
                             "enabled": true,
                             "max_mem": 536870912,
                             "max_file": 536870912,
                             "max_consumers": 200,
                             "max_streams": 300
                           }
                        }`,
			&api.Account{
				JetStream: &api.AccountJetStreamConfig{
					true,
					api.AccountJetStream{
						MaxMemoryStore: intPtr(536870912),
						MaxFileStore:   intPtr(536870912),
						MaxConsumers:   intPtr(200),
						MaxStreams:     intPtr(300),
					},
				},
			},
			nil,
		},
		{
			"create js4 account with jetstream and explicit limits always enables",
			"js4",
			`{
                           "jetstream": {
                             "enabled": false,
                             "max_mem": 536870912,
                             "max_file": 536870912,
                             "max_consumers": 200,
                             "max_streams": 300
                           }
                        }`,
			&api.Account{
				JetStream: &api.AccountJetStreamConfig{
					true,
					api.AccountJetStream{
						MaxMemoryStore: intPtr(536870912),
						MaxFileStore:   intPtr(536870912),
						MaxConsumers:   intPtr(200),
						MaxStreams:     intPtr(300),
					},
				},
			},
			nil,
		},
		{
			"create js5 account with jetstream and unlimited consumers and no streams",
			"js5",
			`{
                           "jetstream": {
                             "max_consumers": -1,
                             "max_streams": 0
                           }
                        }`,
			&api.Account{
				JetStream: &api.AccountJetStreamConfig{
					true,
					api.AccountJetStream{
						MaxConsumers: intPtr(-1),
						MaxStreams:   intPtr(0),
					},
				},
			},
			nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resp, body, err := curl("PUT", host+"/v1/auth/accounts/"+test.account, []byte(test.payload))
			if err != nil {
				t.Fatal(err)
			}
			if test.err != nil {
				if resp.StatusCode == 200 {
					t.Fatalf("Expected error, got success")
				}
				got := string(body)
				expected := test.err.Error() + "\n"
				if got != expected {
					t.Errorf("\nExpected: %+v\n     Got: %+v", expected, got)
				}

				return
			}

			if resp.StatusCode != 200 {
				t.Fatalf("Expected OK, got: %v", resp.StatusCode)
			}
			acc, err := s.getAccountResource(test.account)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(test.expected, acc) {
				t.Errorf("Expected: %+v\nGot: %+v", test.expected, acc)
			}
		})
	}

	// Create a user in each of the accounts.
	t.Run("publishing with multiple users using v2 endpoint", func(t *testing.T) {
		accounts := []string{"js1", "js2", "js3", "js4", "js5", ""}
		for _, acc := range accounts {
			var username string
			if acc == "" {
				username = "global-user"
			} else {
				username = fmt.Sprintf("%s-user", acc)
			}

			payload := `{
	                          "username": "%s",
	                          "password": "secret",
	                          "account": "%s"
	                        }`
			payload = fmt.Sprintf(payload, username, acc)

			endpoint := fmt.Sprintf("%s/v1/auth/idents/%s", host, username)
			resp, _, err := curl("PUT", endpoint, []byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("Expected OK, got: %v", resp.StatusCode)
			}
		}

		// Create a Snapshot
		resp, _, err := curl("POST", host+"/v2/auth/snapshot?name=v1", []byte(""))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		// Publish a named snapshot
		resp, _, err = curl("POST", host+"/v2/auth/publish?name=v1", []byte(""))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		// js1 account
		contents, err := os.ReadFile(filepath.Join(s.opts.DataDir, "current", "accounts", "js1.json"))
		if err != nil {
			t.Fatal(err)
		}
		expected := `{
  "users": [
    {
      "username": "js1-user",
      "password": "secret"
    }
  ],
  "jetstream": {}
}
`
		got := string(contents)
		if got != expected {
			t.Errorf("Expected: %q\nGot: %q", expected, got)
		}

		// js2 account
		contents, err = os.ReadFile(filepath.Join(s.opts.DataDir, "current", "accounts", "js2.json"))
		if err != nil {
			t.Fatal(err)
		}
		expected = `{
  "users": [
    {
      "username": "js2-user",
      "password": "secret"
    }
  ],
  "jetstream": {}
}
`
		got = string(contents)
		if got != expected {
			t.Errorf("Expected: %q\nGot: %q", expected, got)
		}

		contents, err = os.ReadFile(filepath.Join(s.opts.DataDir, "current", "accounts", "js3.json"))
		if err != nil {
			t.Fatal(err)
		}
		expected = `{
  "users": [
    {
      "username": "js3-user",
      "password": "secret"
    }
  ],
  "jetstream": {
    "max_mem": 536870912,
    "max_file": 536870912,
    "max_streams": 300,
    "max_consumers": 200
  }
}
`
		got = string(contents)
		if got != expected {
			t.Errorf("Expected: %q\nGot: %q", expected, got)
		}

		contents, err = os.ReadFile(filepath.Join(s.opts.DataDir, "current", "accounts", "js4.json"))
		if err != nil {
			t.Fatal(err)
		}
		expected = `{
  "users": [
    {
      "username": "js4-user",
      "password": "secret"
    }
  ],
  "jetstream": {
    "max_mem": 536870912,
    "max_file": 536870912,
    "max_streams": 300,
    "max_consumers": 200
  }
}
`
		got = string(contents)
		if got != expected {
			t.Errorf("Expected: %q\nGot: %q", expected, got)
		}

		contents, err = os.ReadFile(filepath.Join(s.opts.DataDir, "current", "accounts", "js5.json"))
		if err != nil {
			t.Fatal(err)
		}
		expected = `{
  "users": [
    {
      "username": "js5-user",
      "password": "secret"
    }
  ],
  "jetstream": {
    "max_streams": 0,
    "max_consumers": -1
  }
}
`
		got = string(contents)
		if got != expected {
			t.Errorf("Expected: %q\nGot: %q", expected, got)
		}
	})

	t.Run("get all accounts", func(t *testing.T) {
		resp, body, err := curl("GET", host+"/v1/auth/accounts/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		expected := 5
		var got []interface{}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}

		if len(got) != expected {
			t.Errorf("Expected: %+v\nGot: %+v", expected, len(got))
		}
	})

	t.Run("get one account", func(t *testing.T) {
		resp, _, err := curl("GET", host+"/v1/auth/accounts/js1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected OK, got: %v", resp.StatusCode)
		}

		resp, _, err = curl("GET", host+"/v1/auth/accounts/notexist", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 404 {
			t.Errorf("Expected Not Found, got: %v", resp.StatusCode)
		}
	})

	// Publish and snapshot with the new structure
	resp, _, err := curl("POST", host+"/v2/auth/snapshot?name=new", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v2/auth/publish?name=new", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("DELETE", host+"/v2/auth/snapshot?name=new", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v2/auth/publish", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	// Can't delete account because users are using it.
	resp, _, err = curl("DELETE", host+"/v1/auth/accounts/js1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Errorf("Expected Conflict, got: %v", resp.StatusCode)
	}

	// Delete all users.
	resp, _, err = curl("DELETE", host+"/v1/auth/idents", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	// Now we can delete the acocunt.
	resp, _, err = curl("DELETE", host+"/v1/auth/accounts/js1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	// Method not allowed
	resp, _, err = curl("HEAD", host+"/v1/auth/accounts/js1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 {
		t.Errorf("Expected Method Not Allowed, got: %v", resp.StatusCode)
	}
}

func TestHandleGlobalJetStream(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer s.Shutdown(ctx)
	waitServerIsReady(t, ctx, s)

	intPtr := func(n int64) *int64 {
		return &n
	}
	_ = intPtr

	host := fmt.Sprintf("http://%s:%d", s.opts.Host, s.opts.Port)
	jsEndpoint := fmt.Sprintf("%s/v2/auth/jetstream", host)
	snapshotEndpoint := fmt.Sprintf("%s/v2/auth/snapshot?name=t1", host)
	publishEndpoint := fmt.Sprintf("%s/v2/auth/publish?name=t1", host)

	jsConf := filepath.Join(s.opts.DataDir, "current", "accounts", "jetstream.json")
	accConf := filepath.Join(s.opts.DataDir, "current", "accounts", "auth.conf")

	jsBlock := "jetstream {\n  include \"jetstream.json\"\n}\n"

	// The order in the following tests is important since there
	// is state dependent from each other.
	t.Run("enable jetstream with defaults", func(t *testing.T) {
		if _, _, err := curl("PUT", jsEndpoint, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}

		if _, _, err := curl("POST", snapshotEndpoint, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := curl("POST", publishEndpoint, nil); err != nil {
			t.Fatal(err)
		}

		data, err := os.ReadFile(jsConf)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(data), "{}\n"; got != want {
			t.Error("unexpected jetstream data")
			t.Fatalf("got=%s; want=%s", got, want)
		}

		data, err = os.ReadFile(accConf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(data); !strings.Contains(got, jsBlock) {
			t.Error("unexpected auth.conf")
			t.Fatalf("got=%s; wantContain=%s", got, jsBlock)
		}
	})

	t.Run("enable jetstream with custom opts", func(t *testing.T) {
		conf := `{
		  "store_dir": "/data/nats-server",
		  "max_memory": 1073741824,
		  "max_file": 10737418240,
		  "max_streams": -1,
		  "max_consumers": -1
		}`
		if _, _, err := curl("PUT", jsEndpoint, []byte(conf)); err != nil {
			t.Fatal(err)
		}

		if _, _, err := curl("POST", snapshotEndpoint, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := curl("POST", publishEndpoint, nil); err != nil {
			t.Fatal(err)
		}

		data, err := os.ReadFile(jsConf)
		if err != nil {
			t.Fatal(err)
		}
		wantConf := `{
  "store_dir": "/data/nats-server",
  "max_file": 10737418240,
  "max_streams": -1,
  "max_consumers": -1
}
`
		if got, want := string(data), wantConf; got != want {
			t.Error("unexpected jetstream data")
			t.Fatalf("got=%q; want=%q", got, want)
		}

		data, err = os.ReadFile(accConf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(data); !strings.Contains(got, jsBlock) {
			t.Error("unexpected auth.conf")
			t.Fatalf("got=%s; wantContain=%s", got, jsBlock)
		}
	})

	t.Run("disable jetstream", func(t *testing.T) {
		if _, _, err := curl("DELETE", jsEndpoint, nil); err != nil {
			t.Fatal(err)
		}

		if _, _, err := curl("DELETE", snapshotEndpoint, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := curl("POST", snapshotEndpoint, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := curl("POST", publishEndpoint, nil); err != nil {
			t.Fatal(err)
		}

		data, err := os.ReadFile(jsConf)
		if err == nil {
			t.Fatal("unexpected success, want not exists error")
		}

		data, err = os.ReadFile(accConf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(data); strings.Contains(got, jsBlock) {
			t.Error("unexpected auth.conf")
			t.Fatalf("got=%s", got)
		}
	})

	t.Run("delete non-existing jetstream", func(t *testing.T) {
		if res, _, err := curl("DELETE", jsEndpoint, nil); err != nil {
			t.Fatal(err)
		} else if got, want := res.StatusCode, http.StatusNotFound; got != want {
			t.Error("unexpected error code")
			t.Fatalf("got=%d; want=%d", got, want)
		}
	})
	t.Run("invalid method", func(t *testing.T) {
		if res, _, err := curl("POST", jsEndpoint, nil); err != nil {
			t.Fatal(err)
		} else if got, want := res.StatusCode, http.StatusMethodNotAllowed; got != want {
			t.Error("unexpected error code")
			t.Fatalf("got=%d; want=%d", got, want)
		}
	})
	t.Run("bad PUT request", func(t *testing.T) {
		if res, _, err := curl("PUT", jsEndpoint, nil); err != nil {
			t.Fatal(err)
		} else if got, want := res.StatusCode, http.StatusBadRequest; got != want {
			t.Error("unexpected error code")
			t.Fatalf("got=%d; want=%d", got, want)
		}
	})
}
