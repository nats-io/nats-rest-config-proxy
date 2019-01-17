package test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-acl-proxy/internal/server"
)

func TestBasicRunServer(t *testing.T) {
	opts := &server.Options{
		NoSignals: true,
	}
	s := server.NewServer(opts)
	ctx, done := context.WithCancel(context.Background())

	time.AfterFunc(50*time.Millisecond, func() {
		done()
	})

	err := s.Run(ctx)
	if err != nil && err != context.Canceled {
		t.Fatalf("Unexpected error running server: %s", err)
	}
}
