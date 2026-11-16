FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/logsentry ./cmd/logsentry

FROM alpine:3.21
RUN adduser -D -H appuser
COPY --from=builder /out/logsentry /usr/local/bin/logsentry
USER appuser
EXPOSE 8095
ENTRYPOINT ["logsentry"]
CMD ["serve", "-addr", "0.0.0.0:8095"]
