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
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// logger is the server logger.
type logger struct {
	logger     *log.Logger
	debug      bool
	trace      bool
	infoLabel  string
	warnLabel  string
	errorLabel string
	fatalLabel string
	debugLabel string
	traceLabel string
}

// NewDefaultLogger returns a default logger.
func NewDefaultLogger() *logger {
	prefix := fmt.Sprintf("[%d] ", os.Getpid())
	flags := log.LstdFlags | log.Lmicroseconds
	l := &logger{logger: log.New(os.Stderr, prefix, flags)}
	colorFormat := "[\x1b[%sm%s\x1b[0m] "
	l.debugLabel = fmt.Sprintf(colorFormat, "36", "DBG")
	l.traceLabel = fmt.Sprintf(colorFormat, "33", "TRC")
	l.infoLabel = fmt.Sprintf(colorFormat, "32", "INF")
	l.warnLabel = fmt.Sprintf(colorFormat, "0;93", "WRN")
	l.errorLabel = fmt.Sprintf(colorFormat, "31", "ERR")
	return l
}

// Infof logs an info statement.
func (l *logger) Infof(format string, v ...interface{}) {
	l.logger.Printf(l.infoLabel+format, v...)
}

// Warnf logs an warning statement.
func (l *logger) Warnf(format string, v ...interface{}) {
	l.logger.Printf(l.warnLabel+format, v...)
}

// Errorf logs an error statement.
func (l *logger) Errorf(format string, v ...interface{}) {
	l.logger.Printf(l.errorLabel+format, v...)
}

// Debugf logs a debug statement.
func (l *logger) Debugf(format string, v ...interface{}) {
	if l.debug {
		l.logger.Printf(l.debugLabel+format, v...)
	}
}

// Tracef logs a trace statement.
func (l *logger) Tracef(format string, v ...interface{}) {
	if l.trace {
		l.logger.Printf(l.traceLabel+format, v...)
	}
}

// traceRequests generates an access log for the request.
func (l *logger) traceRequest(req *http.Request, status, size int, start time.Time) {
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
	l.Tracef(`%s - "%s %s %s" %d %d %.6f`,
		host, req.Method, uri, req.Proto, status, size, time.Since(start).Seconds())
}
