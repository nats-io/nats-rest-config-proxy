package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nats-rest-config-proxy/internal/server"
)

func TestTLSSetup(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.Port = 4568
	opts.CaFile = "certs/ca.pem"
	opts.CertFile = "certs/server.pem"
	opts.KeyFile = "certs/server-key.pem"
	s := server.NewServer(opts)
	host := fmt.Sprintf("https://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()

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
}

func TestTLSAuth(t *testing.T) {
	// Create a data directory.
	opts := DefaultOptions()
	opts.Port = 4568
	opts.CaFile = "certs/ca.pem"
	opts.CertFile = "certs/server.pem"
	opts.KeyFile = "certs/server-key.pem"
	opts.HTTPUsers = []string{"CN=cncf.example.com,OU=CNCF", "CN=nats.example.com,OU=NATS.io"}
	s := server.NewServer(opts)
	host := fmt.Sprintf("https://%s:%d", opts.Host, opts.Port)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	time.AfterFunc(2*time.Second, func() {
		s.Shutdown(ctx)
	})
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		done <- struct{}{}
	}()

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
}
