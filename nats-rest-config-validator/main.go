package main

import (
	"fmt"
	"log"

	"github.com/nats-io/nats-rest-config-proxy/internal/server"
)

func main() {
	s := &server.Server{}

	if err := s.VerifySnapshot(); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("OK")
}
