FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN addgroup -S appgroup --gid 1001 && adduser -S appuser --uid 1001 --ingroup appgroup

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /auth-service ./cmd/auth

FROM scratch AS runtime

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

COPY --from=builder /auth-service /auth-service

USER appuser:appgroup

CMD ["/auth-service"]
