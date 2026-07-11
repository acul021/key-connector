# ---- build ----
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --bin key-connector

# ---- runtime ----
FROM debian:bookworm-slim
RUN useradd -r -u 10001 keyconnector && mkdir /data && chown keyconnector /data
COPY --from=build /src/target/release/key-connector /usr/local/bin/key-connector
USER keyconnector
VOLUME ["/data"]
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/key-connector"]
