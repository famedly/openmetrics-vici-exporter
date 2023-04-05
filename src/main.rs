#![allow(dead_code)]

use axum::{
    response::IntoResponse,
    http::{
        StatusCode,
        header::{self}
    },
    extract::State,
    routing::get,
    Router,
};

use prometheus_client::{
    registry::Registry,
    metrics::{
        family::Family,
    }
};

use std::{
//    collections::HashMap,
//    error::Error,
    sync::Arc,
    net::{IpAddr,SocketAddr},
//    path::Path,
};

use serde::Deserialize;

use config::Config;

pub mod vici;
pub mod metrics;


#[derive(Debug, Deserialize)]
struct Configuration {
    vici_socket: String,
    axum_bind_addr: IpAddr,
    axum_bind_port: u16,
}

pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let state: Arc<AppState> = state.clone();
    let mut buffer = String::new();
    prometheus_client::encoding::text::encode(&mut buffer, &state.registry).unwrap();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/openmetrics-text; version=1.0.0; charset=utf-8")],
        buffer,
    )
}

pub struct AppState {
    pub registry: Registry,
    pub vici: vici::VICIState,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = Config::builder()
        .add_source(config::File::with_name("config"))
        .add_source(config::Environment::with_prefix("VICI_EXPORTER"))
        .build()
        .unwrap();
    let mut conf: Configuration = settings.try_deserialize().unwrap();
    let mut vici_client = rsvici::unix::connect(conf.vici_socket).await?;
    let mut vici_state: vici::VICIState;

    let metrics = Arc::new(metrics::Metrics {
        sa_uptime: Family::default(),
    });

    let mut initial_registery = Registry::default();

    initial_registery.register(
        "sa_uptime",
        "How Long a connection has been established",
        metrics.sa_uptime.clone(),
    );

    let mut state = Arc::new(
        AppState {
            registry: initial_registery,
            vici: vici::VICIState::update(&mut vici_client).await?,
        },
    );



    let addr = SocketAddr::from((conf.axum_bind_addr,conf.axum_bind_port));
    let app = Router::new()
        .route("/metrics",get(metrics_handler))
        .with_state(state);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
