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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
	err = ioutil.WriteFile(s.opts.PublishScript, []byte(script), 0755)
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
	result, err := ioutil.ReadFile(filepath.Join(s.opts.DataDir, "artifact.log"))
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
	err = ioutil.WriteFile(s.opts.PublishScript, []byte(script), 0755)
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

	resp, _, err = curl("DELETE", host+"/v1/auth/perms", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 {
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

	resp, _, err = curl("DELETE", host+"/v1/auth/idents", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 {
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
  "users": [
    {
      "username": "first-user",
      "password": "secret"
    },
    {
      "username": "second-user",
      "password": "secret"
    }
  ]
}
`
	got := string(config)
	if expected != got {
		t.Fatalf("Expected: %s\n, got: %s", expected, got)
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

	// Publish the snapshot
	resp, _, err := curl("POST", host+"/v1/auth/snapshot", []byte(""))
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
			// fmt.Println(rr.Body.String())
		})
	}
}
