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
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// Server is the server.
type Server struct {
	mu sync.Mutex

	// opts is the set of options.
	opts *Options

	// quit stops the server.
	quit func()

	// log is the Logger from the server.
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
	ctx, cancelFn := context.WithCancel(ctx)

	// Logging configuration.
	l := NewDefaultLogger()
	l.debug = s.opts.Debug
	l.trace = s.opts.Trace
	if s.opts.LogFile != "" {
		lj := &lumberjack.Logger{
			Filename: s.opts.LogFile,
			// TODO: Parameterize rest of options.
			// MaxSize:    500, // megabytes
			// MaxBackups: 3,
			// MaxAge:     28,   //days
			// Compress:   true, // disabled by default
		}
		l.logger.SetOutput(lj)
		s.quit = func() {
			lj.Close()
			cancelFn()
		}
	} else {
		s.quit = func() { cancelFn() }
	}
	s.log = l

	s.log.Infof("Starting %s v%s", AppName, Version)
	addr := net.JoinHostPort(s.opts.Host, strconv.Itoa(s.opts.Port))
	err := s.ListenAndServe(addr)
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
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// See: https://golang.org/pkg/net/http/#ServeMux.Handle
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, fmt.Sprintf("%s v%s\n", AppName, Version))
	})

	mux.HandleFunc("/v1/auth/accounts", s.HandleAccounts)
	mux.HandleFunc("/v1/auth/accounts/", s.HandleAccount)
	mux.HandleFunc("/v1/auth/idents", s.HandleIdents)
	mux.HandleFunc("/v1/auth/idents/", s.HandleIdent)
	mux.HandleFunc("/v1/auth/perms", s.HandlePerms)
	mux.HandleFunc("/v1/auth/perms/", s.HandlePerm)
	mux.HandleFunc("/v1/auth/snapshot", s.HandleSnapshot)
	mux.HandleFunc("/v1/auth/publish", s.HandlePublish)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
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

// traceRequests generates an access log for the request.
func (s *Server) traceRequest(req *http.Request, status, size int, start time.Time) {
	url := req.URL
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}

	uri := req.RequestURI
	if uri == "" {
		uri = url.RequestURI()
	}

	// 127.0.0.1 - "GET /v1/auth/accounts/cncf HTTP/1.1" 200 148 0.345
	s.log.Tracef(`%s - "%s %s %s" %d %d %.3f`, host, req.Method, uri, req.Proto, status, size, time.Since(start).Seconds())
}

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Infof("Shutting down...")
	err := s.http.Shutdown(ctx)
	if err != nil {
		s.log.Errorf("Error closing http connections: %s", err)
	}
	s.quit()
	return err
}

// SetupSignalHandler enables handling process signals.
func (s *Server) SetupSignalHandler(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

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
		}
	}
}

// Storage directories

func (s *Server) resourcesDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.DataDir + "/" + ResourcesDir
}

func (s *Server) snapshotsDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.DataDir + "/" + SnapshotsDir
}

func (s *Server) currentConfigDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.DataDir + "/" + CurrentConfigDir
}
