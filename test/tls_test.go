package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	gnatsd "github.com/nats-io/nats-server/v2/test"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats-rest-config-proxy/internal/server"
)

func TestTLSSetup(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.CaFile = "certs/ca.pem"
	opts.CertFile = "certs/server.pem"
	opts.KeyFile = "certs/server-key.pem"
	s := server.NewServer(opts)
	host := fmt.Sprintf("https://%s:%d", opts.Host, opts.Port)
	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	go s.Run(ctx)

	// Wait until https healthz is ok
	caCert, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				ServerName: "nats-cluster.default.svc.cluster.local",
			},
		},
	}

	for range time.NewTicker(50 * time.Millisecond).C {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				t.Fatal(ctx.Err())
			}
		default:
		}

		resp, err := client.Get(host + "/healthz")
		if err != nil {
			continue
		}
		if resp != nil && resp.StatusCode == 200 {
			break
		}
	}

	done()
}

func TestTLSAuth(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.CaFile = "certs/ca.pem"
	opts.CertFile = "certs/server.pem"
	opts.KeyFile = "certs/server-key.pem"
	opts.HTTPUsers = []string{"CN=cncf.example.com,OU=CNCF", "CN=nats.example.com,OU=NATS.io"}
	s := server.NewServer(opts)
	host := fmt.Sprintf("https://%s:%d", opts.Host, opts.Port)
	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	go s.Run(ctx)

	// Wait until https healthz is ok.
	caCert, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Correct client
	{
		cert, err := tls.LoadX509KeyPair("certs/cncf-client.pem", "certs/cncf-client-key.pem")
		if err != nil {
			t.Fatal(err)
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					ServerName:   "nats-cluster.default.svc.cluster.local",
					Certificates: []tls.Certificate{cert},
				},
			},
		}

		for range time.NewTicker(50 * time.Millisecond).C {
			select {
			case <-ctx.Done():
				if ctx.Err() == context.Canceled {
					t.Fatal(ctx.Err())
				}
			default:
			}

			resp, err := client.Get(host + "/healthz")
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp != nil && resp.StatusCode == 200 {
				break
			}
		}
	}

	// Incorrect client
	{
		cert, err := tls.LoadX509KeyPair("certs/acme-client.pem", "certs/acme-client-key.pem")
		if err != nil {
			t.Fatal(err)
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					ServerName:   "nats-cluster.default.svc.cluster.local",
					Certificates: []tls.Certificate{cert},
				},
			},
		}

		for range time.NewTicker(50 * time.Millisecond).C {
			select {
			case <-ctx.Done():
				if ctx.Err() == context.Canceled {
					t.Fatal(ctx.Err())
				}
			default:
			}

			resp, err := client.Get(host + "/healthz")
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp != nil && resp.StatusCode == 401 {
				break
			}
		}
	}
	done()

}

func TestTLSAuthFullCycle(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()

	dir, err := ioutil.TempDir("", "acl-proxy-data-dir-")
	if err != nil {
		t.Fatal(err)
	}
	opts.DataDir = dir
	defer os.RemoveAll(dir)

	s := server.NewServer(opts)
	host := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 15*time.Second)
	time.AfterFunc(30*time.Second, func() {
		s.Shutdown(ctx)
		waitServerIsDone(t, ctx, host)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()
	waitServerIsReady(t, ctx, host)

	// Create the permissions
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

	// Create the permissions
	payload = `{
	         "publish": {
	           "deny": [">"]
	          },
	          "subscribe": {
	            "allow": [">"]
	          }
		}`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/admin-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Create a couple of users
	payload = `{
		  "username": "CN=cncf.example.com,OU=CNCF",
	          "permissions": "normal-user"
		}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/cncf-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	payload = `{
		  "username": "CN=acme.example.com,OU=ACME",
	          "permissions": "admin-user"
		}`
	resp, _, err = curl("PUT", host+"/v1/auth/idents/acme-user", []byte(payload))
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

	config := `
	tls {
	  cert_file = "./certs/server.pem"
	  key_file = "./certs/server-key.pem"
	  ca_file = "./certs/ca.pem"
	  verify_and_map = true
	}

	authorization {
	  include "auth.json"
	}

	`
	err = ioutil.WriteFile(dir+"/current/main.conf", []byte(config), 0666)
	if err != nil {
		t.Fatal(err)
	}

	natsd, _ := gnatsd.RunServerWithConfig(dir + "/current/main.conf")
	if natsd == nil {
		t.Fatal("Unexpected error starting a configured NATS server")
	}
	defer natsd.Shutdown()

	errCh := make(chan error, 2)
	ncA, err := nats.Connect("nats://nats-cluster.default.svc.cluster.local:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.ClientCert("./certs/acme-client.pem", "./certs/acme-client-key.pem"),
		nats.RootCAs("./certs/ca.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ncA.Close()
	ncA.Publish("ng.1", []byte("first"))
	ncA.Flush()

	ncB, err := nats.Connect("nats://nats-cluster.default.svc.cluster.local:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			errCh <- err
		}),
		nats.ClientCert("./certs/acme-client.pem", "./certs/acme-client-key.pem"),
		nats.RootCAs("./certs/ca.pem"),
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

	// Add the new permissions
	payload = `{
	         "publish": {
	           "allow": [">"]
	          },
	          "subscribe": {
	            "allow": [">"]
	          }
		}`
	resp, _, err = curl("PUT", host+"/v1/auth/perms/admin-user", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected OK, got: %v", resp.StatusCode)
	}

	// Publish a named snapshot
	resp, _, err = curl("POST", host+"/v1/auth/publish?name=hello", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected OK, got: %v", resp.StatusCode)
	}

	err = natsd.Reload()
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan struct{}, 0)
	ncB.Subscribe(">", func(m *nats.Msg) {
		received <- struct{}{}
	})
	ncB.Publish("ng.3", []byte("third"))
	ncB.Flush()

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server to stop")
	}
}
