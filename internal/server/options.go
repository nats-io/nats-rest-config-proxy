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
}

var DefaultOptions = &Options{
	NoSignals: false,
	Debug:     false,
	Trace:     false,
	Host:      "0.0.0.0",
	Port:      2222,
}

func ConfigureOptions(args []string) (*Options, error) {
	fs := flag.NewFlagSet(AppName, flag.ExitOnError)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options...]\n\n", AppName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n")
	}

	var (
		showVersion bool
		showHelp    bool
		configFile  string
		opts        *Options = DefaultOptions
	)
	fs.BoolVar(&showHelp, "h", false, "Show this message.")
	fs.BoolVar(&showHelp, "help", false, "Show this message.")
	fs.BoolVar(&showVersion, "version", false, "Print version information.")
	fs.BoolVar(&showVersion, "v", false, "Print version information.")
	fs.StringVar(&configFile, "c", "", "Configuration file.")
	fs.StringVar(&configFile, "config", "", "Configuration file.")
	fs.BoolVar(&opts.Debug, "D", false, "Enable Debug logging.")
	fs.BoolVar(&opts.Debug, "debug", false, "Enable Debug logging.")
	fs.StringVar(&opts.Host, "addr", "", "Network host to listen on.")
	fs.StringVar(&opts.Host, "a", "", "Network host to listen on.")
	fs.IntVar(&opts.Port, "port", 0, "Port to listen on.")
	fs.IntVar(&opts.Port, "p", 0, "Port to listen on.")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if showVersion {
		fmt.Fprintf(os.Stderr, "%s v%s\n", AppName, Version)
		os.Exit(0)
	}
	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if configFile != "" {
		err := opts.ProcessConfigFile(configFile)
		if err != nil {
			return nil, err
		}
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
		}
	}

	return nil
}
