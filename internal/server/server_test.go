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
	"io/ioutil"
	"os"
	"testing"
)

func newTestServer() (*Server, error) {
	dir, err := ioutil.TempDir("", "acl-proxy-data-dir-")
	if err != nil {
		return nil, err
	}
	opts := &Options{
		NoSignals: true,
		NoLog:     true,
		Debug:     true,
		Trace:     true,
		Host:      "localhost",
		Port:      4567,
		DataDir:   dir,
	}
	s := &Server{opts: opts}
	return s, nil
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
