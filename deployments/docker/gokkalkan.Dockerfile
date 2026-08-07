# syntax=docker/dockerfile:1
# Build context: repo koku (bkz. deployments/docker/docker-compose.yml)

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gokkalkan ./cmd/gokkalkan

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gokkalkan /gokkalkan
USER nonroot:nonroot
EXPOSE 8090
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
  CMD ["/gokkalkan", "healthcheck"]
ENTRYPOINT ["/gokkalkan"]
