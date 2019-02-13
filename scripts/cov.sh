#!/bin/bash -e
# Run from directory above via ./scripts/cov.sh

rm -rf ./cov
mkdir cov
env GO111MODULE=on go test -v -covermode=atomic -coverprofile=./cov/server.out ./internal/server
env GO111MODULE=on go test -v -covermode=atomic -coverprofile=./cov/api.out ./api
env GO111MODULE=on go test -v -covermode=atomic -coverprofile=./cov/test.out -coverpkg=./internal/server ./test
gocovmerge ./cov/*.out > acc.out
rm -rf ./cov

# If we have an arg, assume travis run and push to coveralls. Otherwise launch browser results
if [[ -n $1 ]]; then
    $HOME/gopath/bin/goveralls -coverprofile=acc.out -service travis-ci
    rm -rf ./acc.out
else
    go tool cover -html=acc.out
fi
