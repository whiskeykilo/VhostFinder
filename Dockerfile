# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build

RUN apk add --no-cache ca-certificates

WORKDIR /src

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/VhostFinder \
    .

FROM gcr.io/distroless/static-debian13:nonroot

USER nonroot:nonroot

COPY --from=build --chown=nonroot:nonroot /out/VhostFinder /usr/local/bin/VhostFinder

ENTRYPOINT ["/usr/local/bin/VhostFinder"]
