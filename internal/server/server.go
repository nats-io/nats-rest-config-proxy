// Copyright 2018 The NATS Authors
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
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// Server is the NATS ACL Proxy server.
type Server struct {
	mu sync.Mutex

	// opts is the set of options.
	opts *Options

	// quit stops the server.
	quit func()

	// log is the logger from the server.
	log *logger

	// http is the http server.
	http *http.Server
}

// NewServer returns a configured server.
func NewServer(opts *Options) *Server {
	if opts == nil {
		opts = &Options{}
	}
	return &Server{
		opts: opts,
	}
}

// Run starts the server.
func (s *Server) Run(ctx context.Context) error {
	if !s.opts.NoSignals {
		go s.SetupSignalHandler(ctx)
	}
	// Cancellation context for the main loop.
	ctx, done := context.WithCancel(ctx)

	// Logging configuration.
	l := NewLogger(s.opts)
	l.debug = s.opts.Debug
	l.trace = s.opts.Trace
	switch {
	case s.opts.LogFile != "":
		lj := &lumberjack.Logger{
			Filename: s.opts.LogFile,
		}
		if s.opts.LogMaxSize > 0 {
			lj.MaxSize = int(s.opts.LogMaxSize)
		}
		if s.opts.LogMaxBackups > 0 {
			lj.MaxBackups = int(s.opts.LogMaxBackups)
		}
		if s.opts.LogMaxAge > 0 {
			lj.MaxAge = int(s.opts.LogMaxAge)
		}

		l.logger.SetOutput(lj)
		s.quit = func() {
			lj.Close()
			done()
		}
		l.rotate = func() error {
			return lj.Rotate()
		}
	case s.opts.NoLog:
		l.logger.SetOutput(ioutil.Discard)
		fallthrough
	default:
		s.quit = func() { done() }
	}
	s.log = l
	s.log.Infof("Starting %s v%s", AppName, Version)

	// Create required directories for storage if not present.
	err := s.setupStoreDirectories()
	if err != nil {
		defer s.quit()
		return err
	}
	addr := net.JoinHostPort(s.opts.Host, strconv.Itoa(s.opts.Port))
	err = s.ListenAndServe(addr)
	if err != nil {
		defer s.quit()
		return err
	}
	s.log.Infof("Listening on %s", addr)

	select {
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ListenAndServe takes the network address and port that
// the HTTP server should bind to and starts it.
func (s *Server) ListenAndServe(addr string) error {
	var (
		l       net.Listener
		useTLS  bool = s.opts.CertFile != ""
		tlsconf *tls.Config
		err     error
	)

	if useTLS {
		s.log.Infof("TLS is required for client connections")
		if tlsconf, err = s.generateTLSConfig(); err == nil {
			l, err = tls.Listen("tcp", addr, tlsconf)
		}
	} else {
		l, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// See: https://golang.org/pkg/net/http/#ServeMux.Handle
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, fmt.Sprintf("%s v%s\n", AppName, Version))
	})
	mux.HandleFunc("/healthz", s.HandleHealthz)
	mux.HandleFunc("/v1/auth/idents/", s.HandleIdent)
	mux.HandleFunc("/v1/auth/perms/", s.HandlePerm)

	mux.HandleFunc("/v1/auth/idents", s.HandleIdents)
	mux.HandleFunc("/v1/auth/perms", s.HandlePerms)
	mux.HandleFunc("/v1/auth/snapshot", s.HandleSnapshot)
	mux.HandleFunc("/v1/auth/snapshot/", s.HandleSnapshot)
	mux.HandleFunc("/v1/auth/publish", s.HandlePublish)
	mux.HandleFunc("/v1/auth/publish/", s.HandlePublish)
	srv := &http.Server{
		Addr:           addr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.http = srv
	go srv.Serve(l)

	return nil
}

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.log.Infof("Shutting down...")
	if s.http != nil {
		err = s.http.Shutdown(ctx)
		if err != nil {
			s.log.Errorf("Error closing http connections: %s", err)
		}
		return err
	}
	s.quit()

	return nil
}

// SetupSignalHandler enables handling process signals.
func (s *Server) SetupSignalHandler(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigCh {
		s.log.Debugf("Trapped '%v' signal\n", sig)

		// If main context already done, then just skip
		select {
		case <-ctx.Done():
			continue
		default:
		}

		switch sig {
		case syscall.SIGINT:
			s.log.Infof("Exiting...")
			os.Exit(0)
			return
		case syscall.SIGTERM:
			// Gracefully shutdown the server.
			s.Shutdown(ctx)
			return
		case syscall.SIGHUP:
			s.log.Infof("Rotating log file...")
			s.log.rotate()
		}
	}
}

// Storage directories

func (s *Server) resourcesDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filepath.Join(s.opts.DataDir, ResourcesDir)
}

func (s *Server) snapshotsDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filepath.Join(s.opts.DataDir, SnapshotsDir)
}

func (s *Server) currentConfigDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filepath.Join(s.opts.DataDir, CurrentConfigDir)
}

// generateTLSConfig the TLS config for https.
func (s *Server) generateTLSConfig() (*tls.Config, error) {
	//  Load in cert and private key
	cert, err := tls.LoadX509KeyPair(s.opts.CertFile, s.opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("error parsing X509 certificate/key pair (%s, %s): %v",
			s.opts.CertFile, s.opts.KeyFile, err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate (%s): %v",
			s.opts.CertFile, err)
	}
	// Create our TLS configuration
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if s.opts.HTTPUsers != nil && len(s.opts.HTTPUsers) > 0 {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		config.ClientAuth = tls.NoClientCert
	}

	// Add in CAs if applicable.
	if s.opts.CaFile != "" {
		rootPEM, err := ioutil.ReadFile(s.opts.CaFile)
		if err != nil || rootPEM == nil {
			return nil, fmt.Errorf("failed to load root ca certificate (%s): %v", s.opts.CaFile, err)
		}
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(rootPEM)
		if !ok {
			return nil, fmt.Errorf("failed to parse root ca certificate")
		}
		config.ClientCAs = pool
	}
	return config, nil
}
