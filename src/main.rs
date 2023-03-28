#![allow(dead_code,non_camel_case_types)] // I don't want to be bothered for case stuff decided upon me by the VICI API

use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result};

use prometheus_client::{
    registry::Registry,
    encoding::{text::encode},
    metrics::{
        family::Family,
        info::Info,
        counter::Counter,
        gauge::Gauge,
        MetricType::Unknown,
    }
};

use std::{
    collections::HashMap,
    error::Error,
    sync::Mutex,
    net::IpAddr,
    path::Path,
};


use futures_util::{
    stream::{TryStreamExt},
    pin_mut,
};

use serde::Deserialize;

use config::Config;

mod vici_structs;


#[derive(Debug, Deserialize)]
struct Configuration {
    vici_socket: String,
    actix_bind_addr: IpAddr,
    actix_bind_port: u16,
    axtix_auth_token: Option<String>,
}

pub async fn metrics_handler(state: web::Data<Mutex<AppState>>) -> Result<HttpResponse> {
    let state = state.lock().unwrap();
    let mut buf = Vec::new();
    encode(&mut buf, &state.registry)?;
    let body = std::str::from_utf8(buf.as_slice()).unwrap().to_string();
    Ok(HttpResponse::Ok()
        .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
        .body(body))
}

pub struct AppState {
    pub registry: Registry,
    pub vici: vici_structs::VICIState,
}

pub struct Metrics {
    sa_uptime: Family<vici_structs::SecurityAssociationLabels, Counter>,
}

impl Metrics {
    pub fn sa_uptime(&self, security_associations: vici_structs::SecurityAssociations) {
        for (sa_name, sa_values) in security_associations.into_iter() {
            self.sa_uptime.get_or_create(&vici_structs::SecurityAssociationLabels{uniqueid: sa_values.uniqueid}).inner(sa_values.established); // "Vertrau mir Bruder"
        }
    }
}
/*
pub fn get_vici_state(client: rsvici::Client) -> Result<vici_structs::VICIState, actix_web::Error>{
    let version: vici_structs::Version = client.request("version", ()).await?;
    let statistics: vici_structs::Statistics = client.request("statistics", ()).await?;
    let connections = client.stream_request::<(), vici_structs::Connections>("list-connections", "list-conn", ());
    pin_mut!(connections);
    while let Some(conn) = connections.try_next().await? {
        println!("{:#?}", conn);
    }

}
*/


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let settings = Config::builder()
        .add_source(config::File::with_name("config"))
        .add_source(config::Environment::with_prefix("VICI_EXPORTER"))
        .build()
        .unwrap();
    let mut conf: Configuration = settings.try_deserialize().unwrap();
    let mut client = rsvici::unix::connect(conf.vici_socket).await?;
    let mut vici_state: vici_structs::VICIState;

    let metrics = web::Data::new(Metrics {
        sa_uptime: Family::default(),
    });

    let mut state = AppState {
        registry: Registry::default(),
        vici: vici_structs::VICIState.update(client),
    };

    state.registry.register(
        "sa_uptime",
        "How Long a connection has been established",
        Box::new(metrics.sa_uptime.clone()),
    );
    let state = web::Data::new(Mutex::new(state));

    HttpServer::new(move || {
        App::new()
            //.app_data(metrics.clone())
            .app_data(state.clone())
            .service(web::resource("/metrics").route(web::get().to(metrics_handler)))
    })
    .bind((conf.actix_bind_addr, conf.actix_bind_port))?
    .run()
    .await
}
