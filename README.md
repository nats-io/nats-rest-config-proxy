[![License][License-Image]][License-Url][![Build][Build-Status-Image]][Build-Status-Url] [![Coverage Status](https://coveralls.io/repos/github/nats-io/nats-rest-config-proxy/badge.svg?branch=master&t=s8FTRY)](https://coveralls.io/github/nats-io/nats-rest-config-proxy?branch=master)[![Version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=go&type=5&v=0.1.0)](https://github.com/nats-io/nats-rest-config-proxy/releases/tag/v0.1.0)

# NATS REST Configuration Proxy

The NATS Server ACL configuration proxy provides a secure REST interface
for modifying access control lists (ACLs), identities (users), and
passwords.  This proxy is designed to facilitate the development of command
line tools and/or user interfaces to remotely update a NATS server
configuration.

Only identities and permissions are supported at this time.

## Getting started

```sh
go get -u github.com/nats-io/nats-rest-config-proxy
```

## Usage

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

### Configuration file

The NATS REST ACL Proxy supports a configuration file.  Authorization based
on the subject attributes of a client certificate is also supported.

```text
listen = '0.0.0.0:4567'

data_dir = 'test/data'

logging {
  debug = true
  trace = true
}

tls {
  ca = 'test/certs/ca.pem'
  cert = 'test/certs/server.pem'
  key = 'test/certs/server-key.pem'
}

auth {
  users = [
    { user = "CN=cncf.example.com,OU=CNCF" }
  ]
}
```

## How it works

The NATS REST Configuration proxy operates using a data directory a
configuration file, and a publish script.

The process is straightforward:

1. Launch the NATS REST Configuration proxy and specify the Authorization
configuration file you'd like to modify.
2. Use the REST API to modify users and permissions.
3. Take a snapshot.  This saves the current work in the data directory.
4. Invoke the publish command to copy a snapshot into the configuration
file and invoke the optional publish script.

### Why a script

A script is used for versatility.  For some, this could be used as
a step in a github devops flow and the script creates a PR with the new configuration
for human eyes to review.  For others, the updated file is copied to remote nodes and
then NATS servers are reloaded with remote commands, e.g. `ssh -t gnatsd -sl reload`.
One could even work on an included NATS server file directly, with changes to be picked
up nightly.  There are many options.

## Developing

```sh
# Build locally using Go modules
$ GO111MODULE=on go run main.go
[41405] 2019/02/11 16:18:52.713366 [INF] Starting nats-rest-config-proxy v0.0.1
[41405] 2019/02/11 16:18:52.713804 [INF] Listening on 0.0.0.0:4567

# To run the tests
$ go test ./... -v
```

Note:  To test locally, you'll need to add a hostname into your `/etc/hosts` file:
`127.0.0.1 nats-cluster.default.svc.cluster.local`

## REST API

The NATS configuration proxy will return the following error codes:

* 200 OK - success
* 404 Not Found - resource was not found
* 405 Method Not Allowed - unsupported operation
* 409 Conflict -  the operation cannot be completed as a dependency will
create an invalid configuration.

| Resource            | GET                                  | POST | PUT               | DELETE                  |
|---------------------|--------------------------------------|------|-------------------|-------------------------|
| /auth/idents        | Get list of identities               | 405  | 405               | Delete all permissions  |
| /auth/idents/(name) | Get specific identity w/ permissions | 405  | Update identity   | Delete named identity   |  
| /auth/perms         | Get list of named permissions sets   | 405  | Create Permission | Delete all permissions  |
| /auth/perms/(name)  | Get specific permission set          | 405  | Update Permission | Delete names permission |

### Identity Add/Update Payload

```text
{“user”: “alice“, “password“: “foo”}
```

NKEY:

```text
{“nkey“ : “UC6NLCN7AS34YOJVCYD4PJ3QB7QGLYG5B5IMBT25VW5K4TNUJODM7BOX”}
```

Certificate subject attributes with permissions:

```text
{“user“ : “CN=rt01.axon.sa.sandbox03.dev.mastercard.int,OU=SCSS”, “permissions” : “normal_user”}
```

### Permission add/update payload

```text
  normal_user : {
    # Can send to foo, bar or baz only.
    publish : {
      “allow” : ["foo", "bar", "baz"]
    }
    # Can subscribe to everything but $SYSTEM prefixed subjects.
    “subscribe” : {
      “deny” : ["$SYSTEM.>"]
    }
  }
```

### Commands

| Command                 | GET | POST | PUT                    | DELETE |
|-------------------------|-----|------|------------------------|--------|
| /healthz                | 200 | 405  | 405                    | 405    |
| /auth/snapshot?name=foo | 405 | snapshot current config  | 405       | deletes named snapshot    |  
| /auth/publish?name=foo  | 405 |  Saves / invokes script  | 405 | 405    |

### Examples

#### Create a permission

```bash
curl -X PUT http://127.0.0.1:4567/v1/auth/perms/sample-user -d '{
 "publish": {
   "allow": ["foo.*", "bar.>"]
  },
  "subscribe": {
    "deny": ["quux"]
  }
}'
```

#### Get a permission

```bash
curl http://127.0.0.1:4567/v1/auth/perms/sample-user
```

#### Create a user

```bash
curl -X PUT http://127.0.0.1:4567/v1/auth/idents/sample-user -d '{
  "username": "sample-user",
  "password": "secret",
  "permissions": "sample-user"
}'
```

#### Get a user

```bash
curl http://127.0.0.1:4567/v1/auth/idents/sample-user
```

#### Build snapshot

```bash
curl -X POST http://127.0.0.1:4567/v1/auth/snapshot?name=snap1
```

#### Publish snapshot

```bash
curl -X POST http://127.0.0.1:4567/v1/auth/publish?name=snap1
```

## License

Unless otherwise noted, the NATS source files are distributed under the Apache Version 2.0 license found in the LICENSE file.

[License-Url]: https://www.apache.org/licenses/LICENSE-2.0
[License-Image]: https://img.shields.io/badge/License-Apache2-blue.svg
[Build-Status-Url]: http://travis-ci.org/nats-io/nats-rest-config-proxy
[Build-Status-Image]: https://travis-ci.org/nats-io/nats-rest-config-proxy.svg?branch=master
[Coverage-Url]: https://coveralls.io/r/nats-io/nats-rest-config-proxy?branch=master
[Coverage-image]: https://coveralls.io/repos/github/nats-io/nats-rest-config-proxy/badge.svg?branch=master
