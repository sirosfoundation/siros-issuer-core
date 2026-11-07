# Multi-stage build for the issuer service (conformance + deployment).
#
# TLS is terminated upstream (verifier-core service convention): the binary
# binds plain HTTP behind a proxy/ingress.

FROM rust:slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY testdata ./testdata
COPY service ./service
RUN cargo build --release --locked -p siros-issuer-service

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/siros-issuer-service /usr/local/bin/
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=5s --retries=20 --start-period=10s \
    CMD curl -sf http://localhost:8080/healthz || exit 1
ENTRYPOINT ["siros-issuer-service"]
CMD ["/etc/siros-issuer/config.toml"]