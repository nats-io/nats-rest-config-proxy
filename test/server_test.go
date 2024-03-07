package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats-rest-config-proxy/internal/server"
	gnatsd "github.com/nats-io/nats-server/v2/test"
	nats "github.com/nats-io/nats.go"
)

func waitServerIsReady(t *testing.T, ctx context.Context, host string) {
	for range time.NewTicker(50 * time.Millisecond).C {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				t.Fatal(ctx.Err())
			}
		default:
		}

		resp, err := http.Get(fmt.Sprintf("%s/healthz", host))
		if err != nil {
			t.Logf("Error: %s", err)
			continue
		}
		if resp != nil && resp.StatusCode == 200 {
			break
		}
	}
}

func waitServerIsDone(t *testing.T, ctx context.Context, host string) {
	for range time.NewTicker(50 * time.Millisecond).C {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				t.Fatal(ctx.Err())
			}
		default:
		}

		resp, err := http.Get(fmt.Sprintf("%s/healthz", host))
		if err == nil && resp.StatusCode != 200 {
			continue
		}
		break
	}
}

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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

var testPort int = 5567

func DefaultOptions() *server.Options {
	opts := &server.Options{
		NoSignals: true,
		NoLog:     true,
		Debug:     true,
		Trace:     true,
		Host:      "localhost",
		Port:      testPort,
		DataDir:   "./data",
	}
	if os.Getenv("DEBUG") == "true" {
		opts.NoLog = false
	}
	testPort += 1

	return opts
}

func TestBasicRunServer(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = 0
	s := server.NewServer(opts)
	ctx, done := context.WithCancel(context.Background())

	time.AfterFunc(100*time.Millisecond, func() {
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
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

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

	config := fmt.Sprintf("\nauthorization {\n include \"auth.json\" \n}\n")
	err = os.WriteFile("./data/current/main.conf", []byte(config), 0666)
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
		expected := `nats: Permissions Violation for Publish to "ng.1"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: Permissions Violation for Publish to "ng.2"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}
}

func TestFullCycleWithAccounts(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Need to create the accounts first, use an empty JSON payload to create them.
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/bar", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fizz", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Block defining users in payload.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"users":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	// Block export without stream or service.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"exports":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	// Block bad imports.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"imports":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"exports":[{"service": "foo.>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Block wildcard services imports only (note this can change in the future)
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fib", []byte(`{"imports":[{"service": { "account": "buzz", "subject": "foo.>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fib", []byte(`{"imports":[{"service": { "account": "buzz", "subject": "foo.help"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("GET", host+"/v1/auth/accounts/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Get all created accounts.
	resp, body, err := curl("GET", host+"/v1/auth/accounts/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	var accsBody []interface{}
	if err := json.Unmarshal(body, &accsBody); err != nil {
		t.Fatal(err)
	}
	if len(accsBody) != 5 {
		t.Fatalf("Expected 5 accounts, got: %v", len(accsBody))
	}

	// DELETE account and make sure we can't GET it.
	resp, _, err = curl("DELETE", host+"/v1/auth/accounts/fizz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("GET", host+"/v1/auth/accounts/fizz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("Expected Not found, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload := `{
	  "username": "foo-user",
	  "password": "secret",
	  "permissions": "normal-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "bar-user",
	  "password": "secret",
          "permissions": "normal-user",
          "account": "bar"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/bar-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "quux-user",
	  "password": "secret",
	  "permissions": "normal-user"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/quux-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create the permissions.
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

	// Create a snapshot.
	resp, _, err = curl("POST", host+"/v1/auth/snapshot?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot.
	resp, _, err = curl("POST", host+"/v1/auth/publish?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	config := `
          # Load the generated accounts.
          include "auth.json"

          authorization {
            # Add users to the global account.
            users = $users
          }

          # Create the users bound to different accounts.
          accounts = $accounts
        `

	err = os.WriteFile("./data-accounts/current/main.conf", []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig("./data-accounts/current/main.conf")
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("nats://foo-user:secret@127.0.0.1:4222",
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

	ncB, err := nats.Connect("nats://bar-user:secret@127.0.0.1:4222",
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

	ncC, err := nats.Connect("nats://quux-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncC.Close()
	ncC.Publish("ng.3", []byte("third"))
	ncC.Flush()

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: Permissions Violation for Publish to "ng.1"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: Permissions Violation for Publish to "ng.2"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	// Users from different accounts should not be able to
	// receive messages between them.
	sA, err := ncA.SubscribeSync("foo")
	if err != nil {
		t.Fatal(err)
	}
	ncA.Flush()
	sB, err := ncB.SubscribeSync("foo")
	if err != nil {
		t.Fatal(err)
	}
	ncB.Flush()
	sC, err := ncC.SubscribeSync("foo")
	if err != nil {
		t.Fatal(err)
	}
	ncC.Flush()

	err = ncB.Publish("foo", []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	ncB.Flush()

	err = ncC.Publish("hello", []byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	ncC.Flush()

	// Connections A and C will not receive the message.
	_, err = sA.NextMsg(500 * time.Millisecond)
	if err == nil {
		t.Error("Expected timeout waiting for message")
	}
	_, err = sC.NextMsg(500 * time.Millisecond)
	if err == nil {
		t.Error("Expected timeout waiting for message")
	}

	// Connection B is sending the message so will receive it.
	_, err = sB.NextMsg(1 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFullCycleWithAccountsImportsExports(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-imports"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Need to create the accounts first, use an empty JSON payload to create them.
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte(`{
          "exports": [
            { "stream": "foo.public.>" },
            { "service": "foo.api", "allow_trace": true }
          ]
        }`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/quux", []byte(`{
          "msg_trace": {
          	"dest": "otel",
            "sampling": 100
          },
          "imports": [
            { "stream": {"account": "foo", "subject": "foo.public.>" }, "allow_trace": true, "prefix": "from" },
            { "service": {"account": "foo", "subject": "foo.api" }, "to": "from.foo.api" }
          ]
        }`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload := `{
	  "username": "foo-user",
	  "password": "secret",
	  "permissions": "normal-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "quux-user",
	  "password": "secret",
	  "permissions": "normal-user",
	  "account": "quux"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/quux-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a snapshot.
	resp, rbytes, err := curl("POST", host+"/v2/auth/snapshot?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v, %q", resp.StatusCode, rbytes)
	}

	// Publish a named snapshot.
	resp, _, err = curl("POST", host+"/v2/auth/publish?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	config := `
          # Load the generated accounts.
          include "accounts/auth.conf"
        `

	err = os.WriteFile("./data-accounts-imports/current/main.conf", []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig("./data-accounts-imports/current/main.conf")
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("nats://foo-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncA.Close()
	go func() {
		for range time.NewTicker(100 * time.Millisecond).C {
			if !ncA.IsConnected() {
				return
			}
			ncA.Publish("foo.public.foo", []byte("hello"))
		}
	}()
	ncA.Flush()

	ncB, err := nats.Connect("nats://quux-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncB.Close()

	ncC, err := nats.Connect("nats://quux-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncC.Close()

	sub, err := ncB.SubscribeSync(">")
	if err != nil {
		t.Fatal(err)
	}
	ncB.Flush()

	msg, err := sub.NextMsg(1 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := msg.Subject
	expected := "from.foo.public.foo"
	if expected != got {
		t.Fatalf("Expected %+v, got: %+v", expected, got)
	}

	ncA.Subscribe("foo.api", func(m *nats.Msg) {
		m.Respond([]byte("PONG"))
	})
	ncA.Flush()

	msg, err = ncB.Request("from.foo.api", []byte("hi"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got = string(msg.Data)
	expected = "PONG"
	if got != expected {
		t.Fatalf("Expected %+v, got: %+v", expected, got)
	}

	// check that tracing works across accounts using otel header
	otel, err := ncB.SubscribeSync("otel")
	if err != nil {
		t.Fatal("otel subscription failed")
	}

	msg = nats.NewMsg("from.foo.api")
	msg.Header.Add("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4737-00f067aa0ba902b7-01")
	err = ncB.PublishMsg(msg)
	if err != nil {
		t.Fatal("publishing traceparent message failed")
	}

	traceMsg, err := otel.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("waiting for trace failed: %v", err)
	}
	var trace natsserver.MsgTraceEvent
	err = json.Unmarshal(traceMsg.Data, &trace)
	if err != nil {
		t.Fatalf("invalid trace: %v", err)
	}
	if len(trace.Events) != 4 {
		t.Fatalf("Expected 4 trace events got %d", len(trace.Events))
	}
}

func TestFullCycleWithAccountsJetStream(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-imports"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	resp, _, err := curl("PUT", host+"/v1/auth/accounts/js-dyn", []byte(`{
		"jetstream": {"enabled": true}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("PUT", host+"/v1/auth/accounts/js-exp", []byte(`{
          "jetstream": {
			 "max_mem": 1024,
			 "max_file": 1024,
			 "max_consumers": 2,
			 "max_streams": 3
		  }
        }`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("PUT", host+"/v1/auth/accounts/no-js", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload := `{
	  "username": "js-dyn-user",
	  "password": "secret",
	  "permissions": "normal-user",
	  "account": "js-dyn"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/js-dyn-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "js-exp-user",
	  "password": "secret",
	  "permissions": "normal-user",
	  "account": "js-exp"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/js-exp-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "no-js-user",
	  "password": "secret",
	  "permissions": "normal-user",
	  "account": "no-js"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/no-js-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a snapshot.
	resp, _, err = curl("POST", host+"/v2/auth/snapshot?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot.
	resp, _, err = curl("POST", host+"/v2/auth/publish?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	config := `
          jetstream: true
          # Load the generated accounts.
          include "accounts/auth.conf"
        `

	err = os.WriteFile("./data-accounts-imports/current/main.conf", []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig("./data-accounts-imports/current/main.conf")
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	if !natsd.JetStreamEnabled() {
		t.Fatal("nats-server doesn't have jetstream enabled")
	}

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("nats://js-dyn-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.UseOldRequestStyle(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncA.Close()

	ncB, err := nats.Connect("nats://js-exp-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.UseOldRequestStyle(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncB.Close()

	ncC, err := nats.Connect("nats://no-js-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.UseOldRequestStyle(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncC.Close()

	// Check JetStream enabled status.
	msg, err := ncA.Request("$JS.API.INFO", []byte("."), 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(msg.Data, []byte("not enabled")) {
		t.Fatal("account should have jetstream enabled")
	}
	got := string(msg.Data)
	expected := `{"type":"io.nats.jetstream.api.v1.account_info_response","memory":0,"storage":0,"streams":0,"consumers":0,"limits":{"max_memory":-1,"max_storage":-1,"max_streams":-1,"max_consumers":-1,"max_ack_pending":-1,"memory_max_stream_bytes":-1,"storage_max_stream_bytes":-1,"max_bytes_required":false},"api":{"total":0,"errors":0}}`
	if got != expected {
		t.Fatalf("Expected %+v, got: %+v", expected, got)
	}

	msg, err = ncB.Request("$JS.API.INFO", []byte("."), 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(msg.Data, []byte("not enabled")) {
		t.Fatal("account should have jetstream enabled")
	}
	got = string(msg.Data)
	expected = `{"type":"io.nats.jetstream.api.v1.account_info_response","memory":0,"storage":0,"streams":0,"consumers":0,"limits":{"max_memory":1024,"max_storage":1024,"max_streams":3,"max_consumers":2,"max_ack_pending":-1,"memory_max_stream_bytes":-1,"storage_max_stream_bytes":-1,"max_bytes_required":false},"api":{"total":0,"errors":0}}`
	if got != expected {
		t.Fatalf("Expected: \n%+v, got: \n%+v", expected, got)
	}

	msg, err = ncC.Request("$JS.API.INFO", []byte("."), 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(msg.Data, []byte("not enabled")) {
		t.Fatal("account should not have jetstream enabled")
	}
}

func TestFullCycleWithAccountsImportsExportsResponsePermissions(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-response-permissions"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Setup the accounts
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte(`{
          "exports": [
            { "service": "foo.api" }
          ]
        }`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/quux", []byte(`{
          "imports": [
            { "service": {"account": "foo", "subject": "foo.api" }, "to": "from.foo.api" }
          ]
        }`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create the permissions for the service
	resp, _, err = curl("PUT", host+"/v1/auth/perms/foo-user", []byte(`{
          "subscribe": {
            "allow": ["foo.api"]
          },
          "publish": {
            "allow": ["foo.api"]
          },
          "allow_responses": {
            "max": 1,
            "expires": "1m"
          }
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create the permissions for the requestor
	resp, _, err = curl("PUT", host+"/v1/auth/perms/quux-user", []byte(`{
         "publish": {
           "allow": ["from.foo.api"]
          },
          "subscribe": {
            "allow": ["_INBOX.>", "from.foo.api"]
          }
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload := `{
	  "username": "foo-user",
	  "password": "secret",
	  "permissions": "foo-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "quux-user",
	  "password": "secret",
	  "permissions": "quux-user",
	  "account": "quux"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/quux-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a snapshot.
	resp, _, err = curl("POST", host+"/v2/auth/snapshot?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot.
	resp, _, err = curl("POST", host+"/v2/auth/publish?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	config := `
          # Load the generated accounts.
          include "accounts/auth.conf"
        `

	err = os.WriteFile("./data-accounts-response-permissions/current/main.conf", []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig("./data-accounts-response-permissions/current/main.conf")
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("nats://foo-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncA.Close()
	go func() {
		for range time.NewTicker(100 * time.Millisecond).C {
			if !ncA.IsConnected() {
				return
			}
			ncA.Publish("foo.public.foo", []byte("hello"))
		}
	}()
	ncA.Flush()

	ncB, err := nats.Connect("nats://quux-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncB.Close()

	ncC, err := nats.Connect("nats://quux-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncC.Close()

	ncA.Subscribe("foo.api", func(m *nats.Msg) {
		m.Respond([]byte("PONG"))
	})
	ncA.Flush()

	msg, err := ncB.Request("from.foo.api", []byte("hi"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := string(msg.Data)
	expected := "PONG"
	if got != expected {
		t.Fatalf("Expected %+v, got: %+v", expected, got)
	}
}

func TestFullCycleWithAccountsWithDuplicatedUsers(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-dup-check"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Need to create the accounts first, use an empty JSON payload to create them.
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/bar", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fizz", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Block defining users in payload.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"users":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	// Block export without stream or service.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"exports":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	// Block bad imports.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"imports":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"exports":[{"service": "foo.>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Block wildcard services imports only (note this can change in the future)
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fib", []byte(`{"imports":[{"service": { "account": "buzz", "subject": "foo.>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fib", []byte(`{"imports":[{"service": { "account": "buzz", "subject": "foo.help"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("GET", host+"/v1/auth/accounts/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Get all created accounts.
	resp, body, err := curl("GET", host+"/v1/auth/accounts/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	var accsBody []interface{}
	if err := json.Unmarshal(body, &accsBody); err != nil {
		t.Fatal(err)
	}
	if len(accsBody) != 5 {
		t.Fatalf("Expected 5 accounts, got: %v", len(accsBody))
	}

	// DELETE account and make sure we can't GET it.
	resp, _, err = curl("DELETE", host+"/v1/auth/accounts/fizz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("GET", host+"/v1/auth/accounts/fizz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("Expected Not found, got: %v", resp.StatusCode)
	}

	// Create a couple of users.
	payload := `{
	  "username": "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US",
	  "permissions": "normal-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Same user but in different accounts.
	payload = `{
	  "username": "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
          "permissions": "normal-user",
          "account": "bar"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/bar-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a snapshot.
	expectedErr1 := `Error: Found duplicated DN based users on multiple accounts! Details: User "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US" from Account "foo" also defined as "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US" on Account: bar` + "\n"
	expectedErr2 := `Error: Found duplicated DN based users on multiple accounts! Details: User "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US" from Account "bar" also defined as "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US" on Account: foo` + "\n"
	resp, body, err = curl("POST", host+"/v2/auth/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	got := string(body)
	if got != expectedErr1 && got != expectedErr2 {
		t.Fatalf("Expected %v OR %v, \ngot: %v", expectedErr1, expectedErr2, got)
	}

	// Publish a named snapshot.
	resp, body, err = curl("POST", host+"/v2/auth/publish", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	if got != expectedErr1 && got != expectedErr2 {
		t.Fatalf("Expected %v OR %v, \ngot: %v", expectedErr1, expectedErr2, got)
	}
}

func TestFullCycleWithAccountsWithDuplicatedUsersWithGlobalAccount(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-dup-check-global"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Need to create the accounts first, use an empty JSON payload to create them.
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/bar", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fizz", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Block defining users in payload.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"users":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	// Block export without stream or service.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"exports":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	// Block bad imports.
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"imports":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("PUT", host+"/v1/auth/accounts/buzz", []byte(`{"exports":[{"service": "foo.>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Block wildcard services imports only (note this can change in the future)
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fib", []byte(`{"imports":[{"service": { "account": "buzz", "subject": "foo.>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected BadRequest, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fib", []byte(`{"imports":[{"service": { "account": "buzz", "subject": "foo.help"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("GET", host+"/v1/auth/accounts/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Get all created accounts.
	resp, body, err := curl("GET", host+"/v1/auth/accounts/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	var accsBody []interface{}
	if err := json.Unmarshal(body, &accsBody); err != nil {
		t.Fatal(err)
	}
	if len(accsBody) != 5 {
		t.Fatalf("Expected 5 accounts, got: %v", len(accsBody))
	}

	// DELETE account and make sure we can't GET it.
	resp, _, err = curl("DELETE", host+"/v1/auth/accounts/fizz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("GET", host+"/v1/auth/accounts/fizz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("Expected Not found, got: %v", resp.StatusCode)
	}

	// Create a couple of users.
	payload := `{
	  "username": "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US",
	  "permissions": "normal-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Same user but in the global account.
	payload = `{
	  "username": "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
          "permissions": "normal-user"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/bar-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a snapshot.
	expectedErr1 := `Error: Found duplicated DN based users on multiple accounts! Details: User "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US" from Account "foo" also defined as "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US" on Account: $G` + "\n"
	expectedErr2 := `Error: Found duplicated DN based users on multiple accounts! Details: User "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US" from Account "$G" also defined as "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US" on Account: foo` + "\n"
	resp, body, err = curl("POST", host+"/v2/auth/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	got := string(body)
	if got != expectedErr1 && got != expectedErr2 {
		t.Fatalf("Expected %v OR %v, \ngot: %v", expectedErr1, expectedErr2, got)
	}

	// Publish a named snapshot.
	resp, body, err = curl("POST", host+"/v2/auth/publish", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	if got != expectedErr1 && got != expectedErr2 {
		t.Fatalf("Expected %v OR %v, \ngot: %v", expectedErr1, expectedErr2, got)
	}
}

func TestFullCycleWithAccountsRDNsPermissionsMerge(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-rdns-merge"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Need to create the accounts first, use an empty JSON payload to create them.
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/bar", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fizz", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("GET", host+"/v1/auth/accounts/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Get all created accounts.
	resp, body, err := curl("GET", host+"/v1/auth/accounts/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	var accsBody []interface{}
	if err := json.Unmarshal(body, &accsBody); err != nil {
		t.Fatal(err)
	}
	if len(accsBody) != 3 {
		t.Fatalf("Expected 3 accounts, got: %v", len(accsBody))
	}

	// Create the permissions.
	payload := `{
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

	// Merge the permissions from multiple users.
	payload = `{
         "publish": {
           "allow": ["quuz"]
          }
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/extended-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users.
	payload = `{
	  "username": "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US",
	  "permissions": "normal-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Same user but with different permissions, they will be merged.
	payload = `{
	  "username": "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
          "permissions": "extended-user",
          "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/bar-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Same user but with different permissions, they will be merged.
	payload = `{
	  "username": "OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
          "permissions": "normal-user"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/global-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v2/auth/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot.
	resp, body, err = curl("POST", host+"/v2/auth/publish", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	fooBytes, err := os.ReadFile(filepath.Join(opts.DataDir, "current", "accounts", "foo.json"))
	if err != nil {
		t.Fatal(err)
	}

	var foo map[string]interface{}
	if err := json.Unmarshal(fooBytes, &foo); err != nil {
		t.Fatal(err)
	}

	fooWant := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
				"permissions": map[string]interface{}{
					"publish": map[string]interface{}{
						"allow": []interface{}{
							"bar",
							"foo",
							"quuz",
						},
					},
					"subscribe": map[string]interface{}{
						"deny": []interface{}{
							"quux",
						},
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(foo, fooWant) {
		t.Fatalf("Expected %#v, got: %#v", fooWant, foo)
	}

	// Now start a server with the config.
	config := `
          tls {
            ca_file = "./certs/rdns/ca.pem"
            cert_file = "./certs/rdns/client-4222.pem"
            key_file = "./certs/rdns/client-4222.key"
            verify_and_map = true
          }
          debug = true
          trace = true

          authorization {
            include "accounts/global.json"
          }

          # Load the generated accounts.
          include "accounts/auth.conf"
        `

	err = os.WriteFile(filepath.Join(opts.DataDir, "current", "main.conf"), []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig(filepath.Join(opts.DataDir, "current", "main.conf"))
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("tls://localhost:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.RootCAs("./certs/rdns/ca.pem"),
		nats.ClientCert("./certs/rdns/client-A.pem", "./certs/rdns/client-A.key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncA.Close()

	ncB, err := nats.Connect("nats://localhost:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.RootCAs("./certs/rdns/ca.pem"),
		nats.ClientCert("./certs/rdns/client-B.pem", "./certs/rdns/client-B.key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	ncB.Flush()
	defer ncB.Close()

	subA, err := ncA.SubscribeSync(">")
	if err != nil {
		t.Fatal(err)
	}
	ncA.Publish("foo", []byte("hello"))
	ncA.Publish("bar", []byte("hello"))
	ncA.Publish("quuz", []byte("hello"))
	ncA.Flush()

	msg, err := subA.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got := msg.Subject
	expected := "foo"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subA.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "bar"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subA.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "quuz"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	subB, err := ncB.SubscribeSync(">")
	if err != nil {
		t.Fatal(err)
	}
	ncB.Publish("foo", []byte("hello"))
	ncB.Publish("bar", []byte("hello"))
	ncB.Publish("quuz", []byte("hello"))
	ncB.Flush()
	msg, err = subB.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "foo"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subB.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "bar"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subB.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "quuz"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	ncA.Publish("denied-to-A", []byte("hello"))
	time.Sleep(500 * time.Millisecond)
	ncB.Publish("denied-to-B", []byte("hello"))

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: Permissions Violation for Publish to "denied-to-A"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for error code")
	}

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: Permissions Violation for Publish to "denied-to-B"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for error code")
	}

	ncC, err := nats.Connect("nats://localhost:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.RootCAs("./certs/rdns/ca.pem"),
		nats.ClientCert("./certs/rdns/client-C.pem", "./certs/rdns/client-C.key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	ncC.Flush()
	defer ncC.Close()

	subC, err := ncC.SubscribeSync(">")
	if err != nil {
		t.Fatal(err)
	}
	ncC.Publish("foo", []byte("hello"))
	ncC.Publish("bar", []byte("hello"))
	ncA.Flush()

	msg, err = subC.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "foo"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}
}

func TestFullCycleWithAccountsRDNsPermissionsMergeThenRepair(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-rdns-merge-then-repair"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Need to create the accounts first, use an empty JSON payload to create them.
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/bar", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	resp, _, err = curl("PUT", host+"/v1/auth/accounts/fizz", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("GET", host+"/v1/auth/accounts/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Get all created accounts.
	resp, body, err := curl("GET", host+"/v1/auth/accounts/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}
	var accsBody []interface{}
	if err := json.Unmarshal(body, &accsBody); err != nil {
		t.Fatal(err)
	}
	if len(accsBody) != 3 {
		t.Fatalf("Expected 3 accounts, got: %v", len(accsBody))
	}

	// Create the permissions.
	payload := `{
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

	// Merge the permissions from multiple users.
	payload = `{
         "publish": {
           "allow": ["quuz"]
          }
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/extended-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users.
	payload = `{
	  "username": "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US",
	  "permissions": "normal-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Same user but with different permissions, they will be merged.
	payload = `{
	  "username": "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
          "permissions": "extended-user",
          "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/bar-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
	  "username": "OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
          "permissions": "normal-user"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/global-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	resp, _, err = curl("POST", host+"/v2/auth/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot.
	resp, body, err = curl("POST", host+"/v2/auth/publish", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Write a config file with repeated equivalent entries.
	data := `
{
  "users": [
    {
      "username": "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
      "permissions": {
        "publish": {
          "allow": [
            "bar",
            "foo",
            "quuz"
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
      "username": "CN=pubsub.nats.acme.int,O=Acme,OU=Foo,L=Los Angeles,ST=California,C=US",
      "permissions": {
        "publish": {
          "allow": [
            "bar.1",
            "foo.2",
            "quuz.3"
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
      "username": "CN=pubsub.nats.acme.int,L=Los Angeles,O=Acme,OU=Foo,ST=California,C=US",
      "permissions": {
        "publish": {
          "allow": [
            "bar.1",
            "foo.2",
            "quuz.3"
          ]
        },
        "subscribe": {
          "deny": [
            "quux.2",
            "quux.3"
          ]
        }
      }
    }
  ]
}
`
	dataDir := filepath.Join(opts.DataDir, "current", "accounts")
	err = os.WriteFile(filepath.Join(dataDir, "foo.json"), []byte(data), 0644)
	if err != nil {
		t.Fatal(err)
	}
	sopts := DefaultOptions()
	sopts.DataDir = dataDir
	s2 := server.NewServer(sopts)
	if err := s2.RunDataDirectoryRepair(); err != nil {
		t.Fatal(err)
	}

	result, err := os.ReadFile(filepath.Join(dataDir, "foo.json"))
	if err != nil {
		t.Fatal(err)
	}
	expected := `{
  "users": [
    {
      "username": "CN=pubsub.nats.acme.int,OU=Foo,O=Acme,L=Los Angeles,ST=California,C=US",
      "permissions": {
        "publish": {
          "allow": [
            "bar",
            "bar.1",
            "foo",
            "foo.2",
            "quuz",
            "quuz.3"
          ]
        },
        "subscribe": {
          "deny": [
            "quux",
            "quux.2",
            "quux.3"
          ]
        }
      }
    }
  ]
}
`
	if string(result) != expected {
		t.Fatalf("Got %q, expected: %q", result, expected)
	}

	// Now start a server with the config.
	config := `
          tls {
            ca_file = "./certs/rdns/ca.pem"
            cert_file = "./certs/rdns/client-4222.pem"
            key_file = "./certs/rdns/client-4222.key"
            verify_and_map = true
          }
          debug = true
          trace = true

          authorization {
            include "accounts/global.json"
          }

          # Load the generated accounts.
          include "accounts/auth.conf"
        `

	err = os.WriteFile(filepath.Join(opts.DataDir, "current", "main.conf"), []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig(filepath.Join(opts.DataDir, "current", "main.conf"))
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("tls://localhost:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.RootCAs("./certs/rdns/ca.pem"),
		nats.ClientCert("./certs/rdns/client-A.pem", "./certs/rdns/client-A.key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncA.Close()

	ncB, err := nats.Connect("nats://localhost:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.RootCAs("./certs/rdns/ca.pem"),
		nats.ClientCert("./certs/rdns/client-B.pem", "./certs/rdns/client-B.key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	ncB.Flush()
	defer ncB.Close()

	subA, err := ncA.SubscribeSync(">")
	if err != nil {
		t.Fatal(err)
	}
	ncA.Publish("foo", []byte("hello"))
	ncA.Publish("bar", []byte("hello"))
	ncA.Publish("quuz", []byte("hello"))
	ncA.Flush()

	msg, err := subA.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got := msg.Subject
	expected = "foo"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subA.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "bar"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subA.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "quuz"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	subB, err := ncB.SubscribeSync(">")
	if err != nil {
		t.Fatal(err)
	}
	ncB.Publish("foo", []byte("hello"))
	ncB.Publish("bar", []byte("hello"))
	ncB.Publish("quuz", []byte("hello"))
	ncB.Flush()
	msg, err = subB.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "foo"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subB.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "bar"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	msg, err = subB.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "quuz"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}

	ncA.Publish("denied-to-A", []byte("hello"))
	time.Sleep(500 * time.Millisecond)
	ncB.Publish("denied-to-B", []byte("hello"))

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: Permissions Violation for Publish to "denied-to-A"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for error code")
	}

	select {
	case err := <-errCh:
		got := err.Error()
		expected := `nats: Permissions Violation for Publish to "denied-to-B"`
		if got != expected {
			t.Errorf("Expected %q, got: %q", expected, got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for error code")
	}

	ncC, err := nats.Connect("nats://localhost:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.RootCAs("./certs/rdns/ca.pem"),
		nats.ClientCert("./certs/rdns/client-C.pem", "./certs/rdns/client-C.key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	ncC.Flush()
	defer ncC.Close()

	subC, err := ncC.SubscribeSync(">")
	if err != nil {
		t.Fatal(err)
	}
	ncC.Publish("foo", []byte("hello"))
	ncC.Publish("bar", []byte("hello"))
	ncA.Flush()

	msg, err = subC.NextMsg(1 * time.Second)
	if err != nil {
		t.Error(err)
	}
	got = msg.Subject
	expected = "foo"
	if got != expected {
		t.Errorf("Expected %q, got: %q", expected, got)
	}
}

func TestFullCycleWithAccountsMapping(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.DataDir = "./data-accounts-mapping"
	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Need to create an account with mapping first.
	resp, _, err := curl("PUT", host+"/v1/auth/accounts/foo", []byte(`{
		"mappings": {
		  "foo": [
			{
		      "destination": "foo.mapped",
			  "weight": "100%"
			}
		  ],
		  "bar": [
		    {
		      "destination": "bar.mapped.1",
		      "weight": "50%"
		    },
		    {
		      "destination": "bar.mapped.2",
		      "weight": "50%"
		    }
		  ],
		  "foo.correct.cluster": [
			{
		      "destination": "foo.correct.cluster.expect.ok",
			  "weight": "100%",
			  "cluster" : "correct"
			}
		  ],
		  "foo.incorrect.cluster": [
			{
		      "destination": "foo.incorrect.cluster.expect.timeout",
			  "weight": "100%",
			  "cluster" : "incorrect"
			}
		  ]		  	  
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a  users
	payload := `{
	  "username": "foo-user",
	  "password": "secret",
	  "permissions": "admin-user",
	  "account": "foo"
	}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/foo-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a snapshot.
	resp, _, err = curl("POST", host+"/v2/auth/snapshot?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot.
	resp, _, err = curl("POST", host+"/v2/auth/publish?name=with-accounts", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}

	config := `
	      cluster {
			name: correct
		  }
          # Load the generated accounts.
          include "accounts/auth.conf"
        `

	err = os.WriteFile("./data-accounts-mapping/current/main.conf", []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig("./data-accounts-mapping/current/main.conf")
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	nc, err := nats.Connect("nats://foo-user:secret@127.0.0.1:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	sub, err := nc.SubscribeSync("foo.mapped")
	if err != nil {
		t.Fatal(err)
	}
	nc.Publish("foo", []byte("hello"))
	nc.Flush()

	_, err = sub.NextMsg(time.Millisecond * 500)
	if err != nil {
		t.Fatalf("Didn't receive message from foo mapping: %v", err)
	}

	sub, err = nc.SubscribeSync("bar.mapped.*")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		nc.Publish("bar", []byte("hello"))
	}
	nc.Flush()

	var cb1, cb2 int
	var msg *nats.Msg
	for i := 0; i < 100; i++ {
		msg, err = sub.NextMsg(time.Millisecond * 500)
		if err != nil {
			t.Fatalf("Didn't receive message from bar mapping: %v", err)
		}
		if msg.Subject == "bar.mapped.1" {
			cb1++
		}
		if msg.Subject == "bar.mapped.2" {
			cb2++
		}
		if cb1 != 0 && cb2 != 0 {
			break
		}
	}
	if cb1 == 0 || cb2 == 0 {
		t.Fatalf("Expected distribution, got bar.mapped.1 (%d), bar.mapped.2 (%d)", cb1, cb2)
	}

	sub, err = nc.SubscribeSync("foo.correct.cluster.expect.ok")
	if err != nil {
		t.Fatal(err)
	}
	nc.Publish("foo.correct.cluster", []byte("hello"))
	nc.Flush()

	_, err = sub.NextMsg(time.Millisecond * 500)
	if err != nil {
		t.Fatalf("Didn't receive message from foo.correct.cluster mapping: %v", err)
	}

	sub, err = nc.SubscribeSync("foo.incorrect.cluster.expect.timeout")
	if err != nil {
		t.Fatal(err)
	}
	nc.Publish("foo.incorrect.cluster", []byte("hello"))
	nc.Flush()

	_, err = sub.NextMsg(time.Millisecond * 500)
	if err == nil {
		t.Fatalf("Recieved message with incorrect cluster: %v", err)
	}
}
