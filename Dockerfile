FROM golang:1.16-alpine AS builder

WORKDIR $GOPATH/src/github.com/nats-io/nats-rest-config-proxy/

MAINTAINER Waldemar Quevedo <wally@synadia.com>

RUN apk add --update git

COPY . .

RUN CGO_ENABLED=0 GO111MODULE=on go build -v -a -tags netgo -installsuffix netgo -ldflags "-s -w" -o /nats-rest-config-proxy

FROM alpine

RUN apk add --update ca-certificates && mkdir -p /nats/bin && mkdir /nats/conf

COPY --from=builder /nats-rest-config-proxy /nats/bin/nats-rest-config-proxy

RUN ln -ns /nats/bin/nats-rest-config-proxy /bin/nats-rest-config-proxy

EXPOSE 4567

ENTRYPOINT ["/bin/nats-rest-config-proxy"]
