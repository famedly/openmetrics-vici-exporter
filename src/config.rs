use anyhow::Result;
use config::Config;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Deserialize)]
pub struct WebServerConfig {
    pub address: IpAddr,
    pub port: u16,
}
impl Into<SocketAddr> for &WebServerConfig {
    fn into(self) -> SocketAddr {
        SocketAddr::from((self.address, self.port))
    }
}

#[derive(Debug, Deserialize)]
pub struct VICIConfig {
    pub socket: String,
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub server: WebServerConfig,
    pub vici: VICIConfig,
}

impl Configuration {
    pub async fn load() -> Result<Configuration> {
        let settings = Config::builder()
            .set_default("vici.socket", "/var/run/charon.vici")?
            .set_default("vici.interval", 10)?
            .set_default("server.address", "0.0.0.0")?
            .set_default("server.port", 8000)?
            .add_source(config::File::with_name("config"))
            .add_source(config::Environment::with_prefix("VICI_EXPORTER").separator("_"))
            .build();
        match settings {
            Ok(body) => Ok(body.try_deserialize().unwrap()),
            Err(err) => Err(err.into()),
        }
    }
}
