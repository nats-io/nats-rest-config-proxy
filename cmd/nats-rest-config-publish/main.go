package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/nats-io/nats-rest-config-proxy/internal/server"
)

const usageStr = `
Options:
    -d, --dir <directory>         Directory for storing data (default: current directory.)
    -s, --snapshot <name>         Snapshot of the configuration (default: latest configuration).
    -h, --help                    Show this message
    -v, --version                 Show version`

func main() {
	rand.Seed(time.Now().UnixNano())

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nats-rest-config-publish [options...]")
		fmt.Fprintln(os.Stderr, usageStr)
	}

	var (
		showVersion   bool
		showHelp      bool
		snapshotName  string
		publishScript string
	)

	opts := &server.Options{
		NoLog: true,
	}
	flag.StringVar(&opts.DataDir, "data", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "dir", ".", "Directory for storing data.")
	flag.StringVar(&opts.DataDir, "d", ".", "Directory for storing data.")
	flag.StringVar(&snapshotName, "s", "", "Snapshot of the configuration (default: latest configuration).")
	flag.StringVar(&snapshotName, "snapshot", "", "Snapshot of the configuration (default: latest configuration).")
	flag.StringVar(&publishScript, "f", "", "Path to an optional script to execute on publish")
	flag.StringVar(&publishScript, "publish-script", "", "Path to an optional script to execute on publish")
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
		fmt.Printf("nats-rest-config-publish %s\n", server.Version)
		os.Exit(0)
	}

	s := server.NewServer(opts)

	if snapshotName == "" {
		snapshotName = server.DefaultSnapshotName

		// Publish latest config as is taking a snapshot too.
		fmt.Printf("Taking %q snapshot...\n", snapshotName)
		if err := s.TakeSnapshot(snapshotName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("Publishing %q snapshot\n", snapshotName)
	if err := s.PublishSnapshot(snapshotName); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	if publishScript != "" {
		// Change the cwd of the command to location of the script.
		fmt.Printf("Executing script: %s\n", publishScript)
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(publishScript)
		cmd.Dir = filepath.Dir(publishScript)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
		output := stdout.String()
		if output != "" {
			fmt.Printf("STDOUT: \n\n%s\n", output)
		}
		output = stderr.String()
		if output != "" {
			fmt.Printf("STDERR: \n\n%s\n", output)
		}
	}

	fmt.Fprintln(os.Stderr, "OK")
}
