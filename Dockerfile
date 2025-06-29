FROM golang:1.24.2-alpine

WORKDIR /headersec

COPY . .

RUN go build -o HeaderSec ./cmd

ENTRYPOINT ["./HeaderSec"]
