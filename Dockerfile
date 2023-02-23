# Build stage
FROM golang:alpine AS build
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -s" -o aws_auth_jwt ./server

RUN apk add -U --no-cache ca-certificates

# Final stage
FROM scratch
COPY --from=build /app/aws_auth_jwt /aws_auth_jwt
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
CMD ["/aws_auth_jwt"]
