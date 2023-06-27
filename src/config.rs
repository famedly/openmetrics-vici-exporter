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
        let mut s = Config::builder();
        if std::fs::metadata("config").is_ok(){
            s = s.add_source(config::File::with_name("config"));
        } else { println!("config file not found. continuing with env vars... ") };

        s = s.add_source(config::Environment::with_prefix("VICI_EXPORTER").separator("_"));
//        s.build().unwrap();
        let conf: Configuration = s.build().unwrap().try_deserialize().unwrap();
        Ok(conf)
    }
}
