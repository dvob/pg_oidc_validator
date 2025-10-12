FROM postgres:18-trixie AS builder

RUN apt-get update

RUN apt-get install -y postgresql-server-dev-18 gcc make libkrb5-dev curl libssl-dev pkg-config

# Get Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

ENV PATH="/root/.cargo/bin:${PATH}"

ENV PGRX_PG_CONFIG_PATH=/usr/bin/pg_config

WORKDIR /build

COPY . .

RUN cargo build --release

FROM postgres:18-trixie

RUN apt-get update \
  && apt-get install -y ca-certificates --no-install-recommends \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/liboidc_validator.so /usr/lib/postgresql/18/lib/oidc_validator.so
