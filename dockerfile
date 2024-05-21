FROM golang:1.18 as builder

LABEL maintainer="Michael Coleman Michael@f5.com"

# Enable Go modules support and disable CGO
ENV GO111MODULE=on \
    CGO_ENABLED=0

WORKDIR /app

# Copy the go mod and sum files first to leverage Docker cache layering
COPY go.mod ./
COPY public ./public 

RUN go mod download

COPY *.go .
# COPY *.sum .

RUN go build -o http-keepalive -v .

FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/http-keepalive .
COPY --from=builder /app/public ./public

EXPOSE 3000

CMD ["./http-keepalive"]