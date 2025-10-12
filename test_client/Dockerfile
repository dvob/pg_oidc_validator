FROM golang:1.25-alpine3.22 AS builder

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

RUN go build -v -o /usr/local/bin/test-client ./...

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=builder /usr/local/bin/test-client /usr/local/bin/test-client

CMD ["/usr/local/bin/test-client"]
