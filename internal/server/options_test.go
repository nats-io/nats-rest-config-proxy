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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOptions(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		conf     string
		expected *Options
		err      error
	}{
		{
			"listen",
			[]string{},
			`listen: 127.0.0.1:8765`,
			&Options{
				Host:    "127.0.0.1",
				Port:    8765,
				DataDir: "./data",
			},
			nil,
		},
		{
			"listen no port",
			[]string{},
			`listen: 0.0.0.0`,
			&Options{},
			errors.New(`address 0.0.0.0: missing port in address`),
		},
		{
			"listen bad port",
			[]string{},
			`listen: "0.0.0.0:asdf"`,
			&Options{},
			errors.New(`strconv.Atoi: parsing "asdf": invalid syntax`),
		},
		{
			"custom data dir",
			[]string{},
			`data_dir: "/tmp"`,
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "/tmp",
			},
			nil,
		},
		{
			"bad data dir",
			[]string{},
			`data_dir: 1234`,
			&Options{},
			errors.New(`invalid data dir: 1234`),
		},
		{
			"tls ca pem",
			[]string{},
			`tls: {
                          ca: "ca.pem"
                        }`,
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "./data",
				CaFile:  "ca.pem",
			},
			nil,
		},
		{
			"tls all certs",
			[]string{},
			`tls: {
                          ca: "ca.pem"
                          cert: "cert.pem"
                          key: "key.pem"
                        }`,
			&Options{
				Host:     "0.0.0.0",
				Port:     4567,
				DataDir:  "./data",
				CaFile:   "ca.pem",
				CertFile: "cert.pem",
				KeyFile:  "key.pem",
			},
			nil,
		},
		{
			"tls bad options",
			[]string{},
			`tls: true
                        `,
			&Options{},
			errors.New(`invalid tls option: true`),
		},
		{
			"auth users list",
			[]string{},
			`auth: {
                          users: [
                            { user = "CN=example.com" }
                          ]
                        }`,
			&Options{
				Host:      "0.0.0.0",
				Port:      4567,
				DataDir:   "./data",
				HTTPUsers: []string{"CN=example.com"},
			},
			nil,
		},
		{
			"auth users list wrong",
			[]string{},
			`auth: {
                          users: [
                            { username = "CN=example.com" }
                          ]
                        }`,
			&Options{},
			errors.New(`invalid auth config option: map[username:CN=example.com]`),
		},
		{
			"logging debug level",
			[]string{},
			`logging: {
                          level = debug
                        }`,
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "./data",
				Debug:   true,
			},
			nil,
		},
		{
			"logging trace level",
			[]string{},
			`logging: {
                          level = trace
                        }`,
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "./data",
				Debug:   true,
				Trace:   true,
			},
			nil,
		},
		{
			"logging debug level",
			[]string{},
			`logging: {
                          debug = true
                        }`,
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "./data",
				Debug:   true,
			},
			nil,
		},
		{
			"logging trace level",
			[]string{},
			`logging: {
                          trace = true
                        }`,
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "./data",
				Trace:   true,
			},
			nil,
		},
		{
			"logging file",
			[]string{},
			`logging: {
                          file = "/tmp/server.log",
                        }`,
			&Options{
				Host:     "0.0.0.0",
				Port:     4567,
				DataDir:  "./data",
				LogFile:  "/tmp/server.log",
				NoColors: true,
			},
			nil,
		},
		{
			"defaults flags",
			[]string{""},
			"",
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "./data",
			},
			nil,
		},
		{
			"debug and trace",
			[]string{"-DV"},
			"",
			&Options{
				Host:    "0.0.0.0",
				Port:    4567,
				DataDir: "./data",
				Debug:   true,
				Trace:   true,
			},
			nil,
		},
		{
			"logfile",
			[]string{"-l", "foo.log"},
			"",
			&Options{
				Host:     "0.0.0.0",
				Port:     4567,
				DataDir:  "./data",
				LogFile:  "foo.log",
				NoColors: true,
			},
			nil,
		},
		{
			"logging file rotation",
			[]string{},
			`logging: {
                          file = false,
                        }`,
			&Options{},
			errors.New(`invalid config option: false`),
		},
		{
			"logging file rotation",
			[]string{},
			`logging: {
                          file = "/tmp/server.log",
                          max_age = 20
                        }`,
			&Options{
				Host:      "0.0.0.0",
				Port:      4567,
				DataDir:   "./data",
				LogFile:   "/tmp/server.log",
				NoColors:  true,
				LogMaxAge: 20,
			},
			nil,
		},
		{
			"logging file rotation",
			[]string{},
			`logging: {
                          file = "/tmp/server.log",
                          max_backups = 20
                        }`,
			&Options{
				Host:          "0.0.0.0",
				Port:          4567,
				DataDir:       "./data",
				LogFile:       "/tmp/server.log",
				NoColors:      true,
				LogMaxBackups: 20,
			},
			nil,
		},
		{
			"logging file rotation",
			[]string{},
			`logging: {
                          file = "/tmp/server.log",
                          max_backups = 20
                        }`,
			&Options{
				Host:          "0.0.0.0",
				Port:          4567,
				DataDir:       "./data",
				LogFile:       "/tmp/server.log",
				NoColors:      true,
				LogMaxBackups: 20,
			},
			nil,
		},
		{
			"logging file rotation",
			[]string{},
			`logging: {
                          file = "foo.log",
                          max_backups: false
                        }`,
			&Options{},
			errors.New(`invalid config option: false`),
		},
		{
			"logging file rotation",
			[]string{},
			`logging: {
                          file = "foo.log",
                          max_size: false
                        }`,
			&Options{},
			errors.New(`invalid config option: false`),
		},
		{
			"logging file rotation",
			[]string{},
			`logging: {
                          file = "foo.log",
                          max_age = false
                        }`,
			&Options{},
			errors.New(`invalid config option: false`),
		},
		{
			"script in config file",
			[]string{},
			`publish_script: "foo.sh"`,
			&Options{
				Host:          "0.0.0.0",
				Port:          4567,
				DataDir:       "./data",
				PublishScript: "foo.sh",
			},
			nil,
		},
		{
			"script in config file",
			[]string{},
			`script: "foo.sh"`,
			&Options{
				Host:          "0.0.0.0",
				Port:          4567,
				DataDir:       "./data",
				PublishScript: "foo.sh",
			},
			nil,
		},
		{
			"script in config file",
			[]string{},
			`script: false`,
			&Options{},
			errors.New(`invalid script file: false`),
		},
		{
			"script flag",
			[]string{"-f", "foo.sh"},
			"",
			&Options{
				Host:          "0.0.0.0",
				Port:          4567,
				DataDir:       "./data",
				PublishScript: "foo.sh",
			},
			nil,
		},
		{
			"script flag",
			[]string{"--publish-script", "foo.sh"},
			"",
			&Options{
				Host:          "0.0.0.0",
				Port:          4567,
				DataDir:       "./data",
				PublishScript: "foo.sh",
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := test.args
			expected := test.expected
			dir, err := os.MkdirTemp("", "acl-proxy-data-dir-")
			if err != nil {
				t.Fatal(err)
			}
			if test.conf != "" {
				file := filepath.Join(dir, "server.conf")
				err = os.WriteFile(file, []byte(test.conf), 0644)
				if err != nil {
					t.Fatal(err)
				}
				args = append(args, "-c", file)
			}
			opts, err := ConfigureOptions(args)
			if err != nil {
				if test.err == nil {
					t.Error(err)
				} else if test.err.Error() != err.Error() {
					t.Error(err)
				}
				return
			}
			if !reflect.DeepEqual(opts, expected) {
				t.Errorf("Expected %+v, got: %+v", expected, opts)
			}
		})
	}
}

func TestTLSConfig(t *testing.T) {
	opts := &Options{
		CertFile: "./../../test/certs/ca-config.json",
		KeyFile:  "./../../test/certs/ca-config.json",
	}
	expectedErr := `error parsing X509 certificate/key pair (./../../test/certs/ca-config.json, ./../../test/certs/ca-config.json): tls: failed to find any PEM data in certificate input`
	s := NewServer(opts)
	_, err := s.generateTLSConfig()
	if err == nil {
		t.Errorf("Expected error when generating config")
	} else if err.Error() != expectedErr {
		t.Errorf("Unexpected error when generating tls config, got: %+v", err)
	}

	opts = &Options{
		CertFile: "./../../test/certs/server.pem",
		KeyFile:  "./../../test/certs/server-key.pem",
	}
	s = NewServer(opts)
	config, err := s.generateTLSConfig()
	if err != nil {
		t.Fatalf("Unexpected error when generating config: %s", err)
	}
	if config.ClientCAs != nil {
		t.Errorf("Expected CA to be not present TLS config")
	}

	opts = &Options{
		CertFile: "./../../test/certs/server.pom",
		KeyFile:  "./../../test/certs/server-key.pem",
	}
	s = NewServer(opts)
	_, err = s.generateTLSConfig()
	if err == nil {
		t.Fatalf("Expected error when generating config: %s", err)
	}

	opts = &Options{
		CertFile: "./../../test/certs/server.pem",
		KeyFile:  "./../../test/certs/server-key.pem",
		CaFile:   "./../../test/certs/ca.pem",
	}
	s = NewServer(opts)
	config, err = s.generateTLSConfig()
	if err != nil {
		t.Fatalf("Unexpected error when generating config: %s", err)
	}
	if config.ClientCAs == nil {
		t.Errorf("Expected CA to be present TLS config")
	}

	opts = &Options{
		CertFile: "./../../test/certs/server.pem",
		KeyFile:  "./../../test/certs/server-key.pem",
		CaFile:   "./../../test/certs/ca.pom",
	}
	s = NewServer(opts)
	config, err = s.generateTLSConfig()
	if err == nil {
		t.Fatalf("Expected error when generating config: %s", err)
	}
}

func TestConfigureBadFile(t *testing.T) {
	f := []string{"-c", "./../../test/certs/server.pom"}
	_, err := ConfigureOptions(f)
	if err == nil {
		t.Fatal("Expected error configuring server")
	}
}
