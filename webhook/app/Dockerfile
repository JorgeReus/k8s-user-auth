FROM golang:alpine

WORKDIR /go/src/app
COPY . .
RUN go build main.go && mv main /usr/bin/webhook_auth
CMD ["/usr/bin/webhook_auth"]
