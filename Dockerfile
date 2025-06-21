FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /auth-service ./cmd/auth

FROM gcr.io/distroless/static-debian12
COPY --from=builder /auth-service /auth-service
EXPOSE 8080

CMD ["/auth-service"]
