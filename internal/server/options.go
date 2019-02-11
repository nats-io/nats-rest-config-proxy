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

	// LogFile is the log file.
	LogFile string

	// DataDir is the directory for the data.
	DataDir string

	// NoLog discards the output of the logger.
	NoLog bool

	// PublishScript is a path to a script for publishing
	// the configuration.
	PublishScript string
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
		opts        *Options = &Options{}
		dv          bool
	)
	fs.BoolVar(&showHelp, "h", false, "Show this message.")
	fs.BoolVar(&showHelp, "help", false, "Show this message.")
	fs.BoolVar(&showVersion, "version", false, "Print version information.")
	fs.BoolVar(&showVersion, "v", false, "Print version information.")
	fs.StringVar(&configFile, "c", "", "Configuration file.")
	fs.StringVar(&configFile, "config", "", "Configuration file.")
	fs.BoolVar(&opts.Debug, "D", false, "Enable Debug logging.")
	fs.BoolVar(&opts.Debug, "debug", false, "Enable Debug logging.")
	fs.BoolVar(&opts.Trace, "V", false, "Enable Trace logging.")
	fs.BoolVar(&opts.Trace, "trace", false, "Enable Trace logging.")
	fs.BoolVar(&dv, "DV", false, "Enable Debug and Trace logging.")

	fs.StringVar(&opts.Host, "addr", "0.0.0.0", "Network host to listen on.")
	fs.StringVar(&opts.Host, "a", "0.0.0.0", "Network host to listen on.")
	fs.IntVar(&opts.Port, "port", 4567, "Port to listen on.")
	fs.IntVar(&opts.Port, "p", 4567, "Port to listen on.")
	fs.StringVar(&opts.DataDir, "data", "./data", "Directory for storing data.")
	fs.StringVar(&opts.DataDir, "dir", "./data", "Directory for storing data.")
	fs.StringVar(&opts.DataDir, "d", "./data", "Directory for storing data.")
	fs.StringVar(&opts.PublishScript, "f", "", "Path to an optional script to execute on publish")
	fs.StringVar(&opts.PublishScript, "publish-script", "", "Path to an optional script to execute on publish")

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
			switch o := v.(type) {
			case string:
				opts.DataDir = o
			}
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
