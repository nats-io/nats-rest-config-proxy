[![License][License-Image]][License-Url][![Build][Build-Status-Image]][Build-Status-Url] [![Coverage][Coverage-Image]][Coverage-Url]

# NATS ACL Configuration Proxy

### Getting started

```sh
go get -u github.com/nats-io/nats-rest-config-proxy
```

### Usage

```sh
Usage: nats-rest-config-proxy [options...]

Server Options:
    -a, --addr <host>             Bind to host address (default: 0.0.0.0)
    -p, --port <port>             Use port for clients (default: 4567)
    -d, --dir <directory>         Directory for storing data
    -c, --config <file>           Configuration file
    -f, --publish-script <file>   Path to an optional script to execute on publish

Logging Options:
    -l, --log <file>              File to redirect log output
    -D, --debug                   Enable debugging output
    -V, --trace                   Enable trace logging
    -DV                           Debug and trace

TLS Options:
    --cert <file>                 Server certificate file
    --key <file>                  Private key for server certificate
    --cacert <file>               Client certificate CA for verification

Common Options:
    -h, --help                    Show this message
    -v, --version                 Show version
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


[License-Url]: https://www.apache.org/licenses/LICENSE-2.0
[License-Image]: https://img.shields.io/badge/License-Apache2-blue.svg
[Build-Status-Url]: http://travis-ci.org/nats-io/nats-rest-config-proxy
[Build-Status-Image]: https://travis-ci.org/nats-io/nats-rest-config-proxy.svg?branch=master
[Coverage-Url]: https://coveralls.io/r/nats-io/nats-rest-config-proxy?branch=master
[Coverage-image]: https://coveralls.io/repos/github/nats-io/nats-rest-config-proxy/badge.svg?branch=master