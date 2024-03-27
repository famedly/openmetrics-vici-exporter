# openmetrics-vici-exporter

Provides an openmetrics compatible endpoint for strongSwan charon's VICI.


## Features

as of `v0.1.0` the following metrics are exporterd:

| name | |
|------|-|
|`sa_uptime`| seconds since state changed to up |
|`sa_rekey_time`||

| name |
|`sa_child_bytes_in`|
|`sa_child_bytes_out`|
|`sa_child_packets_in`|
|`sa_child_packets_out`|

### Planned Features:
* `v0.2.0`
    * an info metric showing the applied configuration
    * an enum metric showing the current state / queued jobs per connection

## Usage

### Deployment
You have a few options avalible:
1. [Binary Releases](/releases)
2. Docker Image
    * `docker-oss.nexus.famedly.de/openmetrics-vici-exporter

### Configuration

All values have defaults, no configuration is necessary, but an exhaustive default configuration is still provided, see [`config.yml`](/blob/main/config.yml).

You can also set these as environment variables, prefixed with `VICI_EXPORTER`

| Key | Default | |
|-----|---------|-|
|`vici.socket`|`/var/run/charon.vici`| unix socket where vici is reachable |
|`vici.interval`|`10`| how often to get data from the vici, in seconds |
|`server.address`|`0.0.0.0`| any bind address, ipv6 is also allowed `[::1]`|
|`server.port`|`8000`||

## Development

if you'd like to contribute you are free to do so.

we provide a nix flake (`nix develop`) to setup the rust enviroment for you, but there's still some manual setup to do.

you need charon running with the vici plugin enabled in the configuration.

make sure your user has the required permissions to access the vici socket.

on a debian system you can just run the following to give yourself access:

``` bash
sudo groupadd vici
sudo chown root:vici /var/run/charon.vici
sudo chmod 0770 /var/run/charon.vici
sudo usermod -aG vici $(whoami)
```

` cargo run && curl http://[::1]:8001/metrics `

## License

[AGPL-3.0-only](LICENSE.md)

## Authors

This software is authored and maintained as open-source by Famedly's Infrastructure Team.

- Evelyn Alicke <e.alicke@famedly.com>
- Famedly GmbH <info@famedly.com>
