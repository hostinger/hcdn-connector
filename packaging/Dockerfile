# Build: docker build -f packaging/Dockerfile --build-arg VERSION=0.1.0 -t hcdn-connector .
# Base images are pinned by digest; bump the tag and digest together.
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
ARG VERSION=0.0.0-dev
ARG COMMIT=
ARG DATE=
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/hcdn-connector ./cmd/hcdn-connector
# Runtime dir for the admin socket, owned by nonroot (65532); distroless has no shell to mkdir.
RUN mkdir -p /out/run/hcdn-connector /out/etc/hcdn-connector && chmod 0750 /out/run/hcdn-connector /out/etc/hcdn-connector

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/hcdn-connector /usr/bin/hcdn-connector
COPY --from=build --chown=65532:65532 /out/run/hcdn-connector /run/hcdn-connector
COPY --from=build --chown=65532:65532 /out/etc/hcdn-connector /etc/hcdn-connector
COPY packaging/config.example.yml LICENSE NOTICE /usr/share/doc/hcdn-connector/
# Mount /etc/hcdn-connector (config.yml + credentials.json, mode 0600, uid 65532).
VOLUME ["/etc/hcdn-connector"]
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/hcdn-connector"]
CMD ["run", "--config", "/etc/hcdn-connector/config.yml"]
