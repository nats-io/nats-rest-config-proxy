FROM golang:1.11-alpine3.8 AS builder

WORKDIR $GOPATH/src/github.com/nats-io/nats-acl-config-proxy/

MAINTAINER Waldemar Quevedo <wally@synadia.com>

RUN apk add --update git

COPY . .

RUN pwd && ls -la

RUN cd $GOPATH/src/github.com/nats-io/nats-acl-config-proxy/cmd/nats-acl-config-proxy && CGO_ENABLED=0 go build -v -a -tags netgo -installsuffix netgo -ldflags "-s -w" -o /nats-acl-config-proxy

FROM alpine:3.8

RUN apk add --update ca-certificates && mkdir -p /nats/bin && mkdir /nats/conf

COPY --from=builder /nats-acl-config-proxy /nats/bin/nats-acl-config-proxy

RUN ln -ns /nats/bin/nats-acl-config-proxy /bin/nats-acl-config-proxy

EXPOSE 4567

ENTRYPOINT ["/bin/nats-acl-config-proxy"]
