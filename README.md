# NATS ACL Configuration Proxy

### Getting started

```sh
go get -u github.com/nats-io/nats-rest-config-proxy
```

### Usage

```sh
$ nats-rest-config-proxy -h
Usage: nats-rest-config-proxy [options...]

  -D	Enable Debug logging.
  -V	Enable Trace logging.
  -a string
    	Network host to listen on. (default "0.0.0.0")
  -c string
    	Configuration file.
  -d string
    	Directory for storing data. (default "./data")
  -dir string
    	Directory for storing data. (default "./data")
  -f string
    	Path to an optional script to execute on publish
  -h	Show this message.
  -p int
    	Port to listen on. (default 4567)
  -publish-script string
    	Path to an optional script to execute on publish
  -v	Print version information.
```

### Developing

```sh
# Build locally using Go modules
$ GO111MODULE=on go run cmd/nats-rest-config-proxy/main.go
[41405] 2019/02/11 16:18:52.713366 [INF] Starting nats-rest-config-proxy v0.0.1
[41405] 2019/02/11 16:18:52.713804 [INF] Listening on 0.0.0.0:4567

# To run the tests
$ go test ./... -v
```

### License

Unless otherwise noted, the NATS source files are distributed under the Apache Version 2.0 license found in the LICENSE file.
