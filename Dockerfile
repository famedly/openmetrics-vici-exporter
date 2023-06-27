FROM registry.gitlab.com/famedly/infra/containers/rust:main as builder
COPY . /app
WORKDIR /app

RUN cargo build --release

FROM debian:stable-slim
RUN mkdir -p /opt/openmetrics-vici-exporter
WORKDIR /opt/openmetrics-vici-exporter
COPY --from=builder /app/target/release/openmetrics-vici-exporter /usr/local/bin/openmetrics-vici-exporter
CMD ["/usr/local/bin/openmetrics-vici-exporter"]
