package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nats-io/nats-rest-config-proxy/internal/server"
)

const usageStr = `
Options:
    -d, --dir <directory>         Directory for storing data (default is the current directory.)
    -h, --help                    Show this message
    -v, --version                 Show version`

var (
	version = "0.0.0"
)

func main() {
	server.Version = version

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nats-rest-config-fix [options...]")
		fmt.Fprintln(os.Stderr, usageStr)
	}

	var (
		showVersion   bool
		showHelp      bool
		debugAndTrace bool
	)

	opts := &server.Options{}
	flag.StringVar(&opts.DataDir, "data", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "dir", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "d", ".", "Directory for storing data.")
	flag.BoolVar(&showVersion, "v", false, "Show version.")
	flag.BoolVar(&showVersion, "version", false, "Show version.")
	flag.BoolVar(&showHelp, "h", false, "Show help.")
	flag.BoolVar(&showHelp, "help", false, "Show help.")
	flag.BoolVar(&opts.Debug, "D", false, "Show debug logs.")
	flag.BoolVar(&opts.Trace, "V", false, "Show trace logs.")
	flag.BoolVar(&debugAndTrace, "DV", false, "Show debug and trace logs.")
	flag.Parse()

	switch {
	case showHelp:
		flag.Usage()
		os.Exit(0)
	case showVersion:
		fmt.Printf("nats-rest-config-fix %s\n", server.Version)
		os.Exit(0)
	}
	if debugAndTrace {
		opts.Debug = true
		opts.Trace = true
	}

	s := server.NewServer(opts)
	if err := s.RunDataDirectoryRepair(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "OK")
}
