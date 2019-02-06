package test

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	gnatsd "github.com/nats-io/gnatsd/test"
	"github.com/nats-io/go-nats"
	"github.com/nats-io/nats-acl-proxy/internal/server"
)

func curl(method string, endpoint string, payload []byte) (*http.Response, []byte, error) {
	result, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, err
	}
	e := fmt.Sprintf("%s://%s%s", result.Scheme, result.Host, result.Path)
	buf := bytes.NewBuffer([]byte(payload))
	req, err := http.NewRequest(method, e, buf)
	if err != nil {
		return nil, nil, err
	}
	if len(result.Query()) > 0 {
		for k, v := range result.Query() {
			req.URL.Query().Add(k, string(v[0]))
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

func DefaultOptions() *server.Options {
	return &server.Options{
		NoSignals: true,
		NoLog:     false,
		Debug:     true,
		Trace:     true,
		Host:      "localhost",
		Port:      4567,
		DataDir:   "./data",
	}
}

func TestBasicRunServer(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = 0
	s := server.NewServer(opts)
	ctx, done := context.WithCancel(context.Background())

	time.AfterFunc(50*time.Millisecond, func() {
		done()
	})

	err := s.Run(ctx)
	if err != nil && err != context.Canceled {
		t.Fatalf("Unexpected error running server: %s", err)
	}
}

func TestFullCycle(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()

	// Create a couple of users
	payload := `{
	  "username": "user-a",
	  "password": "secret",
          "permissions": "normal-user"
	}`
	resp, _, err := curl("PUT", host+"/v1/auth/idents/user-a", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "user-b",
	  "password": "secret",
          "permissions": "normal-user"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/user-b", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create the permissions
	payload = `{
         "publish": {
           "allow": ["foo", "bar"]
          },
          "subscribe": {
            "deny": ["quux"]
          }
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/normal-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a Snapshot
	resp, _, err = curl("POST", host+"/v1/auth/snapshot?name=hello", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot
	resp, _, err = curl("POST", host+"/v1/auth/publish?name=hello", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	// Inspect the resulting file
	// contents, err := ioutil.ReadFile("./data/snapshots/hello.json")
	// if err != nil {
	// 	t.Fatal(err)
	// }

	config := fmt.Sprintf("\nauthorization {\n include \"auth.json\" \n}\n")
	err = ioutil.WriteFile("./data/current/main.conf", []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}
	natsd, _ := gnatsd.RunServerWithConfig("./data/current/main.conf")
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("nats://user-a:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncA.Close()
	ncA.Publish("ng.1", []byte("first"))
	ncA.Flush()

	ncB, err := nats.Connect("nats://user-b:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncB.Close()
	ncB.Publish("ng.2", []byte("second"))
	ncB.Flush()

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: permissions violation for publish to "ng.1"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", got, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: permissions violation for publish to "ng.2"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", got, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}
}
