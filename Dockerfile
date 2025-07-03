FROM golang:1.24.2-alpine

WORKDIR /headersec


COPY go.mod go.sum ./
RUN go mod download


COPY . .


RUN go build -o HeaderSec .

ENTRYPOINT ["./HeaderSec"]
