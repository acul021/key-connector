# ---- chef ----
# cargo-chef splits the build so dependencies compile in their own layer,
# keyed on the recipe below rather than on the source tree. Installed from
# crates.io instead of pulling a third-party builder image.
FROM rust:1-slim AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src

# ---- plan ----
FROM chef AS plan
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo chef prepare --recipe-path recipe.json

# ---- build ----
FROM chef AS build
# The recipe only changes when Cargo.toml/Cargo.lock do, so this layer (the
# expensive one) stays cached across source-only changes.
COPY --from=plan /src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
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
