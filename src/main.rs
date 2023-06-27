use metrics::{
    describe_gauge, 
    gauge, 
    describe_counter,
    counter, 
    IntoLabels, 
    Unit};
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::time::{interval, Duration, MissedTickBehavior};

pub mod config;
pub mod vici;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let conf = config::Configuration::load().await?;
    let mut vici_client = rsvici::unix::connect(conf.vici.socket).await?;

    let mut interval = interval(Duration::from_secs(conf.vici.interval));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    PrometheusBuilder::new()
        .with_http_listener(&conf.server)
        .install()
        .expect("failed to install recorder/exporter");

    describe_gauge!("sa_uptime", Unit::Seconds, "");
    describe_gauge!("sa_rekey_time", Unit::Seconds, "");

    describe_counter!("sa_child_bytes_out", Unit::Bytes, "");
    describe_counter!("sa_child_bytes_in", Unit::Bytes, "");

    loop {
        let vici_state = vici::VICIState::update(&mut vici_client).await?;

        for (sa_name, sa_values) in vici_state.security_associations {
            let mut labels = sa_values.into_labels();
            labels.push((&("sa_name", sa_name.clone())).into());

            gauge!("sa_uptime", sa_values.established as f64, labels.clone());
            gauge!("sa_rekey_time", sa_values.rekey_time as f64, labels.clone());
            //gauge!("sa_state")
            for (sa_child_name, sa_child_values) in sa_values.child_security_associations {
                let mut child_labels = sa_child_values.into_labels();
                child_labels.push((&("sa_name", sa_name.clone())).into());
                child_labels.push((&("sa_child_name", sa_child_name)).into());
                counter!("sa_child_bytes_in", sa_child_values.bytes_in, child_labels.clone());
                counter!("sa_child_bytes_out", sa_child_values.bytes_out, child_labels.clone());
                counter!("sa_child_packets_in", sa_child_values.packets_in, child_labels.clone());
                counter!("sa_child_packets_out", sa_child_values.packets_out, child_labels.clone());
            
            }
        }
        interval.tick().await;
    }
}
