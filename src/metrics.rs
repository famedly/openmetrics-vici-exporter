use prometheus_client::{
    metrics::{
        family::Family,
        gauge::Gauge,
    }
};
use anyhow::Result;

use crate::vici;
pub mod labels;

pub struct Metrics {
    pub sa_uptime: Family<labels::SecurityAssociationLabels, Gauge>,
}

impl Metrics {
    pub async fn sa_uptime(&self, security_associations: vici::SecurityAssociations) -> Result<()>{
        for named_sa in security_associations.into_iter() {
            let label_set = labels::SecurityAssociationLabels::set_from_sa(&mut named_sa).await?;
            let (_sa_name, sa_value) = named_sa;
            self.sa_uptime.get_or_create(&label_set).set(sa_value.established as i64);
        }
        Ok(());
    }
}
