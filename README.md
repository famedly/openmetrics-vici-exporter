[![CI](https://github.com/famedly/openmetrics-vici-expoter/actions/workflows/build.yml/badge.svg?event=release)](https://github.com/famedly/openmetrics-vici-expoter/actions/workflows/build.yml)

# openmetrics-vici-exporter

provides an openmetrics compatible endpoint for strongSwan charon's VICI.
initally tested against strongSwan 5.9 and strongSwan 6.0.

## deployment
pull container image from `ghcr.io`, see `docker-compose.yml` in this repo


## development

1. `sudo groupadd vici`
2. `sudo chown root:vici /var/run/charon.vici`
3. `sudo chmod 0770 /var/run/charon.vici`
4. `sudo usermod -aG vici $user`
5. `cargo run`
6. `curl http://localhost:8001/metrics`


## license

[AGPL-3.0-only](LICENSE.md)

## authors

- Evelyn Alicke <e.alicke@famedly.com>
