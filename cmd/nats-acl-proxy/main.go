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

package main

import (
	"context"
	"log"
	"os"
	"runtime"

	"github.com/nats-io/nats-acl-proxy/internal/server"
)

func main() {
	// Use flags to define the options
	opts := &server.Options{}

	s := server.NewServer(opts)
	log.Printf("Starting NATS ACL Proxy v%s\n", server.Version)
	log.Printf("Go Version: %s\n", runtime.Version())

	err := s.Run(context.Background())
	if err != nil && err != context.Canceled {
		log.Println(err.Error())
		os.Exit(1)
	}
}
