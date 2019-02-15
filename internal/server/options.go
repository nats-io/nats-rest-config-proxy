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
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/nats-io/gnatsd/conf"
)

var usageStr = `
Server Options:
    -a, --addr <host>             Bind to host address (default: 0.0.0.0)
    -p, --port <port>             Use port for clients (default: 4567)
    -d, --dir <directory>         Directory for storing data
    -c, --config <file>           Configuration file
    -f, --publish-script <file>   Path to an optional script to execute on publish

Logging Options:
    -l, --log <file>              File to redirect log output
    -D, --debug                   Enable debugging output
    -V, --trace                   Enable trace logging
    -DV                           Debug and trace

TLS Options:
    --cert <file>                 Server certificate file
    --key <file>                  Private key for server certificate
    --cacert <file>               Client certificate CA for verification

Common Options:
    -h, --help                    Show this message
    -v, --version                 Show version
`

// usage will print out the flag options for the server.
func usage() {
	fmt.Printf("%s\n", usageStr)
}

// Options for the server.
type Options struct {
	// NoSignals marks whether to enable the signal handler.
	NoSignals bool

	// Debug enables debug messages.
	Debug bool

	// Trace enables trace messages.
	Trace bool

	// Host is the network to listen on.
	Host string

	// Port is the network port for the server.
	Port int

	// LogFile is the log file.
	LogFile string

	// DataDir is the directory for the data.
	DataDir string

	// NoLog discards the output of the logger.
	NoLog bool

	// NoColors disables the colors in the logger.
	NoColors bool

	// PublishScript is a path to a script for publishing
	// the configuration.
	PublishScript string

	// CaFile is the cert with the CA for TLS.
	CaFile string

	// CertFile is the TLS cert for the server.
	CertFile string

	// KeyFile is the key for TLS from the server.
	KeyFile string

	// VerifyAndMap verifies the client certificate.
	VerifyAndMap bool

	// HTTPUsers are the users that can connect to the server.
	HTTPUsers []string
}

func ConfigureOptions(args []string) (*Options, error) {
	fs := flag.NewFlagSet(AppName, flag.ExitOnError)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options...]\n", AppName)
		fmt.Fprintf(os.Stderr, usageStr)
		fmt.Fprintf(os.Stderr, "\n")
	}

	var (
		showVersion bool
		showHelp    bool
		configFile  string
		opts        *Options = &Options{}
		dv          bool
	)
	fs.BoolVar(&showHelp, "h", false, "Show this message.")
	fs.BoolVar(&showHelp, "help", false, "Show this message.")
	fs.BoolVar(&showVersion, "version", false, "Print version information.")
	fs.BoolVar(&showVersion, "v", false, "Print version information.")
	fs.StringVar(&configFile, "c", "", "Configuration file.")
	fs.StringVar(&configFile, "config", "", "Configuration file.")
	fs.StringVar(&opts.Host, "addr", "0.0.0.0", "Network host to listen on.")
	fs.StringVar(&opts.Host, "a", "0.0.0.0", "Network host to listen on.")
	fs.IntVar(&opts.Port, "port", 4567, "Port to listen on.")
	fs.IntVar(&opts.Port, "p", 4567, "Port to listen on.")
	fs.StringVar(&opts.DataDir, "data", "./data", "Directory for storing data.")
	fs.StringVar(&opts.DataDir, "dir", "./data", "Directory for storing data.")
	fs.StringVar(&opts.DataDir, "d", "./data", "Directory for storing data.")
	fs.StringVar(&opts.PublishScript, "f", "", "Path to an optional script to execute on publish")
	fs.StringVar(&opts.PublishScript, "publish-script", "", "Path to an optional script to execute on publish")
	fs.BoolVar(&opts.Debug, "D", false, "Enable Debug logging.")
	fs.BoolVar(&opts.Debug, "debug", false, "Enable Debug logging.")
	fs.BoolVar(&opts.Trace, "V", false, "Enable Trace logging.")
	fs.BoolVar(&opts.Trace, "trace", false, "Enable Trace logging.")
	fs.BoolVar(&dv, "DV", false, "Enable Debug and Trace logging.")
	fs.StringVar(&opts.LogFile, "l", "", "File to redirect log output.")
	fs.StringVar(&opts.LogFile, "log", "", "File to redirect log output.")
	fs.StringVar(&opts.CertFile, "cert", "", "Server certificate file (Enables HTTPS).")
	fs.StringVar(&opts.KeyFile, "key", "", "Private key for server certificate (used with HTTPS).")
	fs.StringVar(&opts.CaFile, "cacert", "", "Client certificate CA for verification (used with HTTPS).")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	switch {
	case showVersion:
		fmt.Fprintf(os.Stderr, "%s v%s\n", AppName, Version)
		os.Exit(0)
	case showHelp:
		flag.Usage()
		os.Exit(0)
	case configFile != "":
		err := opts.ProcessConfigFile(configFile)
		if err != nil {
			return nil, err
		}
	}

	if dv {
		opts.Debug = true
		opts.Trace = true
	}
	if opts.LogFile != "" {
		opts.NoColors = true
	}

	return opts, nil
}

func (opts *Options) ProcessConfigFile(configFile string) error {
	m, err := conf.ParseFile(configFile)
	if err != nil {
		return err
	}

	for k, v := range m {
		switch k {
		case "listen":
			switch o := v.(type) {
			case string:
				host, port, err := net.SplitHostPort(o)
				if err != nil {
					return err
				}
				opts.Host = host
				opts.Port, err = strconv.Atoi(port)
				if err != nil {
					return err
				}
			}
		case "data_dir":
			if o, ok := v.(string); ok {
				opts.DataDir = o
			} else {
				return fmt.Errorf("invalid data dir: %+v", v)
			}
		case "tls":
			m, ok := v.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid tls option: %+v", v)
			}
			for k, v := range m {
				switch k {
				case "ca":
					o, ok := v.(string)
					if !ok {
						return fmt.Errorf("invalid config option: %+v", v)
					}
					opts.CaFile = o
				case "cert":
					o, ok := v.(string)
					if !ok {
						return fmt.Errorf("invalid config option: %+v", v)
					}
					opts.CertFile = o
				case "key":
					o, ok := v.(string)
					if !ok {
						return fmt.Errorf("invalid config option: %+v", v)
					}
					opts.KeyFile = o
				}
			}
		case "auth":
			m, ok := v.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid auth config option: %+v", v)
			}
			users, ok := m["users"]
			if !ok {
				return fmt.Errorf("invalid auth config option: %+v", v)
			}
			httpUsers := make([]string, 0)
			for _, v := range users.([]interface{}) {
				mu, ok := v.(map[string]interface{})
				if !ok {
					return fmt.Errorf("invalid auth config option: %+v", v)
				}
				u, ok := mu["user"].(string)
				if !ok {
					return fmt.Errorf("invalid auth config option: %+v", v)
				}
				httpUsers = append(httpUsers, u)
			}
			opts.HTTPUsers = httpUsers
		case "logging":
			m, ok := v.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid config option: %+v", v)
			}
			for k, v := range m {
				switch k {
				case "level":
					o, ok := v.(string)
					if !ok {
						return fmt.Errorf("invalid config option: %+v", v)
					}
					switch o {
					case "debug":
						opts.Debug = true
					case "trace":
						opts.Debug = true
						opts.Trace = true
					}
				case "debug":
					o, ok := v.(bool)
					if !ok {
						return fmt.Errorf("invalid config option: %+v", v)
					}
					opts.Debug = o
				case "trace":
					o, ok := v.(bool)
					if !ok {
						return fmt.Errorf("invalid config option: %+v", v)
					}
					opts.Trace = o
				case "file":
					o, ok := v.(string)
					if !ok {
						return fmt.Errorf("invalid config option: %+v", v)
					}
					opts.LogFile = o
				}
			}
		}
	}

	return nil
}
