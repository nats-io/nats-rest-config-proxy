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
    -d, --dir <directory>         Directory for storing data
    -h, --help                    Show this message
    -v, --version                 Show version
`

func main() {
	rand.Seed(time.Now().UnixNano())

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nats-rest-config-validator [options...]")
		fmt.Fprintln(os.Stderr, usageStr)
	}

	opts := &server.Options{
		NoLog: true,
	}
	flag.StringVar(&opts.DataDir, "data", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "dir", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "d", ".", "Directory for storing data.")
	flag.Parse()

	s := server.NewServer(opts)
	if err := s.VerifySnapshot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "OK")
}
