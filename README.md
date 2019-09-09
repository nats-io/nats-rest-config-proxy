[![License][License-Image]][License-Url][![Build][Build-Status-Image]][Build-Status-Url] [![Coverage Status](https://coveralls.io/repos/github/nats-io/nats-rest-config-proxy/badge.svg?branch=master&t=s8FTRY)](https://coveralls.io/github/nats-io/nats-rest-config-proxy?branch=master)[![Version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=go&type=5&v=0.2.0)](https://github.com/nats-io/nats-rest-config-proxy/releases/tag/v0.2.0)

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

```hcl
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
{“username”: “alice“, “password“: “foo”}
```

NKEY:

```text
{“nkey“ : “UC6NLCN7AS34YOJVCYD4PJ3QB7QGLYG5B5IMBT25VW5K4TNUJODM7BOX”}
```

Certificate subject attributes with permissions:

```text
{“username“ : “CN=rt01.axon.sa.sandbox03.dev.mastercard.int,OU=SCSS”, “permissions” : “normal_user”}
```

### Permission add/update payload

```text
  "normal_user" : {
    # Can send to foo, bar or baz only.
    "publish" : {
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

## Usage Walkthrough

In this example, we will create a couple of users with different permissions:

| Ident     | DN in TLS cert              | Permissions |
|-----------|-----------------------------|-------------|
| acme-user | CN=acme.example.com,OU=ACME | admin       |
| cncf-user | CN=cncf.example.com,OU=CNCF | guest       |

First we will start the server, and use the `-d` flag to setup the directory that will contain the users that were created via the proxy:

```
$ mkdir config
$ nats-rest-config-proxy -DV -d config
[5875] 2019/06/18 14:43:44.826782 [INF] Starting nats-rest-config-proxy v0.1.0
[5875] 2019/06/18 14:43:44.829134 [INF] Listening on 0.0.0.0:4567
```

Next, let's create the permissions for both `guest` and `admin` users:

```sh
curl -X PUT http://127.0.0.1:4567/v1/auth/perms/guest -d '{
 "publish": {
   "allow": ["foo.*", "bar.>"]
  },
  "subscribe": {
    "deny": ["quux"]
  }
}'

curl -X PUT http://127.0.0.1:4567/v1/auth/perms/admin -d '{
 "publish": {
   "allow": [">"]
  },
  "subscribe": {
    "allow": [">"]
  }
}'
```

Now that we have created the permissions, let's bind some users to these permissions:

```sh
curl -X PUT http://127.0.0.1:4567/v1/auth/idents/cncf-user -d '{
  "username": "CN=cncf.example.com,OU=CNCF",
  "permissions": "guest"
}'

curl -X PUT http://127.0.0.1:4567/v1/auth/idents/acme-user -d '{
  "username": "CN=acme.example.com,OU=ACME",
  "permissions": "admin"
}'
```

We now can create a named snapshot for this setup. Let's create one named `v1`:

```sh
curl -X POST http://127.0.0.1:4567/v1/auth/snapshot?name=v1
```

Then publish the configuration:

```sh
curl -X POST http://127.0.0.1:4567/v1/auth/publish?name=v1
```

At this point, we will have the following directory structure in the config directory:

```
 tree config
config
├── current
│   └── auth.json
├── resources
│   ├── permissions
│   │   ├── admin.json
│   │   └── guest.json
│   └── users
│       ├── acme-user.json
│       └── cncf-user.json
└── snapshots
    └── v1.json
```

And the published auth configuration will look like:

```js
$ cat config/current/auth.json 
{
  "users": [
    {
      "username": "CN=acme.example.com,OU=ACME",
      "permissions": {
        "publish": {
          "allow": [
            ">"
          ]
        },
        "subscribe": {
          "allow": [
            ">"
          ]
        }
      }
    },
    {
      "username": "CN=cncf.example.com,OU=CNCF",
      "permissions": {
        "publish": {
          "allow": [
            "foo.*",
            "bar.>"
          ]
        },
        "subscribe": {
          "deny": [
            "quux"
          ]
        }
      }
    }
  ]
}
```

This configuration can now be included by a `nats-server`. Note that in order to enable checking permissions based on a TLS certificate, it is needed to set `verify_and_map=` to `true` in the `tls` config:

```conf
tls {
  cert_file = "./certs/server.pem"
  key_file = "./certs/server-key.pem"
  ca_file = "./certs/ca.pem"
  verify_and_map = true
}

authorization {
  include "config/current/auth.json"
}
```

Starting the NATS Server with the configuration:

```
nats-server -c nats.conf  -DV
[6342] 2019/06/18 18:04:38.899054 [INF] Starting nats-server version 2.0.0
[6342] 2019/06/18 18:04:38.899177 [DBG] Go build version go1.12
[6342] 2019/06/18 18:04:38.899557 [INF] Listening for client connections on 0.0.0.0:4222
[6342] 2019/06/18 18:04:38.899570 [INF] TLS required for client connections
[6342] 2019/06/18 18:04:38.899578 [INF] Server id is NCFA6C5OC45PKJOISSDCWBEDQ4YMKOH57WHCWLL6EZ2Y723WAAIUHPJI
[6342] 2019/06/18 18:04:38.899584 [INF] Server is ready
```

Now if the following app tries to connect and publish to a subject without permissions it won't be able to:

```go
package main

import (
	"log"

	"github.com/nats-io/nats.go"
)

func main() {
	nc, err := nats.Connect("nats://nats-cluster.default.svc.cluster.local:4222",
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Println("Error:", err)
		}),
		nats.ClientCert("./certs/cncf-client.pem", "./certs/cnfc-client-key.pem"),
		nats.RootCAs("./certs/ca.pem"),
	)
	if err != nil {
		log.Fatal(err)
	}
	nc.Publish("ng", []byte("first"))
	nc.Publish("foo.bar", []byte("second"))
	nc.Flush()
	nc.Drain()
}
```

Example logs from the server:

```
[6404] 2019/06/18 18:10:11.921048 [DBG] 127.0.0.1:55492 - cid:1 - Client connection created
[6404] 2019/06/18 18:10:11.921561 [DBG] 127.0.0.1:55492 - cid:1 - Starting TLS client connection handshake
[6404] 2019/06/18 18:10:11.929261 [DBG] 127.0.0.1:55492 - cid:1 - TLS handshake complete
[6404] 2019/06/18 18:10:11.929367 [DBG] 127.0.0.1:55492 - cid:1 - TLS version 1.2, cipher suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
[6404] 2019/06/18 18:10:11.929615 [TRC] 127.0.0.1:55492 - cid:1 - <<- [CONNECT {"verbose":false,"pedantic":false,"tls_required":true,"name":"","lang":"go","version":"1.7.0","protocol":1,"echo":true}]
[6404] 2019/06/18 18:10:11.929782 [DBG] 127.0.0.1:55492 - cid:1 - User in cert [""], not found
[6404] 2019/06/18 18:10:11.929801 [DBG] 127.0.0.1:55492 - cid:1 - Using certificate subject for auth ["CN=cncf.example.com,OU=CNCF"]
[6404] 2019/06/18 18:10:11.929833 [TRC] 127.0.0.1:55492 - cid:1 - <<- [PING]
[6404] 2019/06/18 18:10:11.929843 [TRC] 127.0.0.1:55492 - cid:1 - ->> [PONG]
[6404] 2019/06/18 18:10:11.930454 [TRC] 127.0.0.1:55492 - cid:1 - <<- [PUB ng 5]
[6404] 2019/06/18 18:10:11.930470 [TRC] 127.0.0.1:55492 - cid:1 - <<- MSG_PAYLOAD: ["first"]
[6404] 2019/06/18 18:10:11.930498 [TRC] 127.0.0.1:55492 - cid:1 - ->> [-ERR Permissions Violation for Publish to "ng"]
[6404] 2019/06/18 18:10:11.930567 [ERR] 127.0.0.1:55492 - cid:1 - Publish Violation - User "CN=cncf.example.com,OU=CNCF", Subject "ng"
[6404] 2019/06/18 18:10:11.930583 [TRC] 127.0.0.1:55492 - cid:1 - <<- [PUB foo.bar 6]
[6404] 2019/06/18 18:10:11.930608 [TRC] 127.0.0.1:55492 - cid:1 - <<- MSG_PAYLOAD: ["second"]
[6404] 2019/06/18 18:10:11.930629 [TRC] 127.0.0.1:55492 - cid:1 - <<- [PING]
[6404] 2019/06/18 18:10:11.930661 [TRC] 127.0.0.1:55492 - cid:1 - ->> [PONG]
[6404] 2019/06/18 18:10:11.931113 [DBG] 127.0.0.1:55492 - cid:1 - Client connection closed
```

## Using NATS v2.0 Accounts 

In this example, we will create a couple of users on different accounts.

| Ident        | Account          | Permissions |
|--------------|------------------|-------------|
| foo-1-user   | Foo              | guest       |
| foo-2-user   | Foo              | admin       |
| bar-1-user   | Bar              | guest	|
| bar-2-user   | Bar              | admin	|

Start the server using its own data directory:

```
$ mkdir config
$ nats-rest-config-proxy -DV -d config
[5875] 2019/06/18 14:43:44.826782 [INF] Starting nats-rest-config-proxy v0.1.0
[5875] 2019/06/18 14:43:44.829134 [INF] Listening on 0.0.0.0:4567
```

Next, let's create the permissions for both `guest` and `admin` users:

```sh
curl -X PUT http://127.0.0.1:4567/v1/auth/perms/guest -d '{
 "publish": {
   "allow": ["foo.*", "bar.>"]
  },
  "subscribe": {
    "deny": ["quux"]
  }
}'

curl -X PUT http://127.0.0.1:4567/v1/auth/perms/admin -d '{
 "publish": {
   "allow": [">"]
  },
  "subscribe": {
    "allow": [">"]
  }
}'
```

Now that we have created the permissions, let's bind some users to these permissions:

```sh
curl -X PUT http://127.0.0.1:4567/v1/auth/idents/foo-1-user -d '{
  "username": "foo-1-user",
  "password": "foo-1-secret",
  "permissions": "guest",
  "account": "Foo"
}'

curl -X PUT http://127.0.0.1:4567/v1/auth/idents/foo-2-user -d '{
  "username": "foo-2-user",
  "password": "foo-2-secret",
  "permissions": "admin",
  "account": "Foo"
}'

curl -X PUT http://127.0.0.1:4567/v1/auth/idents/bar-1-user -d '{
  "username": "bar-1-user",
  "password": "bar-1-secret",
  "permissions": "guest",
  "account": "Bar"
}'

curl -X PUT http://127.0.0.1:4567/v1/auth/idents/bar-2-user -d '{
  "username": "bar-2-user",
  "password": "bar-2-secret",
  "permissions": "admin",
  "account": "Bar"
}'
```

We now can create a named snapshot for this setup. Let's create one named `v1`:

```sh
curl -X POST http://127.0.0.1:4567/v1/auth/snapshot?name=v1
```

Then publish the configuration:

```sh
curl -X POST http://127.0.0.1:4567/v1/auth/publish?name=v1
```

At this point, we will have the following directory structure in the config directory:

```
tree config
config
├── current
│   └── auth.json
├── resources
│   ├── permissions
│   │   ├── admin.json
│   │   └── guest.json
│   └── users
│       ├── bar-1-user.json
│       ├── bar-2-user.json
│       ├── foo-1-user.json
│       └── foo-2-user.json
└── snapshots
    └── v1.json
```

And the published auth configuration will look like:

```js
$ cat config/current/auth.json 
{
  "users": [],
  "accounts": {
    "Bar": {
      "users": [
        {
          "username": "bar-1-user",
          "password": "bar-1-secret",
          "permissions": {
            "publish": {
              "allow": [
                "foo.*",
                "bar.>"
              ]
            },
            "subscribe": {
              "deny": [
                "quux"
              ]
            }
          }
        },
        {
          "username": "bar-2-user",
          "password": "bar-2-secret",
          "permissions": {
            "publish": {
              "allow": [
                ">"
              ]
            },
            "subscribe": {
              "allow": [
                ">"
              ]
            }
          }
        }
      ]
    },
    "Foo": {
      "users": [
        {
          "username": "foo-1-user",
          "password": "foo-1-secret",
          "permissions": {
            "publish": {
              "allow": [
                "foo.*",
                "bar.>"
              ]
            },
            "subscribe": {
              "deny": [
                "quux"
              ]
            }
          }
        },
        {
          "username": "foo-2-user",
          "password": "foo-2-secret",
          "permissions": {
            "publish": {
              "allow": [
                ">"
              ]
            },
            "subscribe": {
              "allow": [
                ">"
              ]
            }
          }
        }
      ]
    }
  }
}
```

This configuration can now be included by a `nats-server` in order to define a couple of variables that can be used as follow:

```conf
include "config/current/auth.json"

authorization {
  # Add users to the global account.
  users = $users
}

# Create the users bound to different accounts.
accounts = $accounts

```

## Our sponsor for this project

Many thanks to [MasterCard](http://mastercard.com) for sponsoring this project.
We appreciate MasterCard's support of NATS, CNCF, and the OSS community.

## License

Unless otherwise noted, the NATS source files are distributed under the Apache Version 2.0 license found in the LICENSE file.

[License-Url]: https://www.apache.org/licenses/LICENSE-2.0
[License-Image]: https://img.shields.io/badge/License-Apache2-blue.svg
[Build-Status-Url]: http://travis-ci.org/nats-io/nats-rest-config-proxy
[Build-Status-Image]: https://travis-ci.org/nats-io/nats-rest-config-proxy.svg?branch=master
[Coverage-Url]: https://coveralls.io/r/nats-io/nats-rest-config-proxy?branch=master
[Coverage-image]: https://coveralls.io/repos/github/nats-io/nats-rest-config-proxy/badge.svg?branch=master
