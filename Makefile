
all: build
GOOS?=darwin

FLAGS=
GOOS?=darwin
GIT_COMMIT =$(shell sh -c 'git log --pretty=format:'%h' -n 1')
BUILD_TIME= $(shell sh -c 'date -u '+%Y-%m-%dT%H:%M:%SZ'')

include $(ENV_FILE)
export

build: clean 
	$(ENVVAR) GOOS=$(GOOS) go build \
	    -o authenticator \
		-ldflags="-X 'github.com/devtron-labs/authenticator/util.GitCommit=${GIT_COMMIT}' -X 'github.com/devtron-labs/authenticator/util.BuildTime=${BUILD_TIME}'"

wire:
	wire

clean:
	rm -f authenticator

run: build
	./authenticator



