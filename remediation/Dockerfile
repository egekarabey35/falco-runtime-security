FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o remediation main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /app/remediation /remediation
USER 65532:65532
ENTRYPOINT ["/remediation"]
