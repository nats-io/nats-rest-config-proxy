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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats-acl-config-proxy/api"
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

	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go s.Run(ctx)
	defer func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, s)
	}()

	for range time.NewTicker(50 * time.Millisecond).C {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				t.Fatal()
			}
		default:
		}

		resp, err := http.Get("http://127.0.0.1:4567/healthz")
		if err != nil {
			t.Logf("Error: %s", err)
			continue
		}
		if resp.StatusCode == 200 {
			break
		}
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

	resp, _, err := curl("DELETE", host+"/v1/auth/perms/second-user", []byte(""))
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
