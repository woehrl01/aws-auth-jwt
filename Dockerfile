# Build stage
FROM golang:alpine AS build
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -s" -o aws_auth_jwt ./server

# Final stage
FROM scratch
COPY --from=build /app/aws_auth_jwt /aws_auth_jwt
CMD ["/aws_auth_jwt"]