FROM golang:1.20-alpine3.17 AS build-env
USER root
RUN apk add --no-cache git gcc musl-dev
RUN apk add --update make
RUN go install github.com/google/wire/cmd/wire@latest
WORKDIR /go/src/github.com/devtron-labs/authenticator
ADD . /go/src/github.com/devtron-labs/authenticator/
RUN GOOS=linux make

FROM alpine:3.17.0
RUN apk add --no-cache ca-certificates
RUN apk add git --no-cache
COPY --from=build-env  /go/src/github.com/devtron-labs/authenticator/authenticator .

RUN adduser -D devtron
RUN chown -R devtron:devtron ./authenticator
USER devtron

CMD ["./authenticator"]