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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func newTestServer() (*Server, error) {
	dir, err := ioutil.TempDir("", "acl-proxy-data-dir-")
	if err != nil {
		return nil, err
	}
	opts := &Options{
		NoSignals: true,
		NoLog:     false,
		Debug:     true,
		Trace:     true,
		Host:      "localhost",
		Port:      4567,
		DataDir:   dir,
	}
	s := &Server{opts: opts}
	return s, nil
}

func waitServerIsReady(t *testing.T, ctx context.Context, s *Server) {
	for range time.NewTicker(50 * time.Millisecond).C {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				t.Fatal(ctx.Err())
			}
		default:
		}

		resp, err := http.Get(fmt.Sprintf("http://%s:%d/healthz", s.opts.Host, s.opts.Port))
		if err != nil {
			t.Logf("Error: %s", err)
			continue
		}
		if resp.StatusCode == 200 {
			break
		}
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
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

func TestServerSetup(t *testing.T) {
	s, err := newTestServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(s.opts.DataDir)
	err = s.setupStoreDirectories()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(s.resourcesDir())
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(s.snapshotsDir())
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(s.currentConfigDir())
	if err != nil {
		t.Error(err)
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
	defer s.Shutdown(ctx)

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
