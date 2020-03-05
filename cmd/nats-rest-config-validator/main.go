package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/nats-io/nats-rest-config-proxy/internal/server"
)

const usageStr = `
Options:
    -d, --dir <directory>         Directory for storing data (default is the current directory.)
    -h, --help                    Show this message
    -v, --version                 Show version
`

func main() {
	rand.Seed(time.Now().UnixNano())

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nats-rest-config-validator [options...]")
		fmt.Fprintln(os.Stderr, usageStr)
	}

	var (
		showVersion bool
		showHelp    bool
	)

	opts := &server.Options{
		NoLog: true,
	}
	flag.StringVar(&opts.DataDir, "data", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "dir", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "d", ".", "Directory for storing data.")
	flag.BoolVar(&showVersion, "v", false, "Show version.")
	flag.BoolVar(&showVersion, "version", false, "Show version.")
	flag.BoolVar(&showHelp, "h", false, "Show help.")
	flag.BoolVar(&showHelp, "help", false, "Show help.")
	flag.Parse()

	switch {
	case showHelp:
		flag.Usage()
		os.Exit(0)
	case showVersion:
		fmt.Printf("nats-rest-config-validator %s\n", server.Version)
		os.Exit(0)
	}

	s := server.NewServer(opts)
	if err := s.VerifySnapshot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "OK")
}
