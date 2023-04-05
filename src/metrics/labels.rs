use serde::Deserialize;
use prometheus_client::encoding::{EncodeLabelValue,EncodeLabelSet};

use crate::vici;
use anyhow::Result;


// I don't really wanna define *all* of this here, it's gonna get really tedious and uncomfortable to maintain.

/*
#[derive(Debug, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct SecurityAssociationLabels {
    pub uniqueid: String,
    pub local_id: String,
    pub local_host: String,
    pub local_port: u16,
    pub remote_id: String,
    pub remote_host: String,
    pub remote_port: u16,
}
*/
#[derive(Debug, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct SecurityAssociationInfo {
    pub uniqueid:       String,
    pub version:        u8,
    pub local_host:     String,
    pub local_port:     u16,
    pub local_id:       String,
    pub remote_host:    String,
    pub remote_port:    u16,
    pub remote_id:      String,
    pub if_id_in:       String,
    pub if_id_out:      String,
    pub encr_alg:       String,
    pub encr_keysize:   String,
    pub integ_alg:      String,
    pub integ_keysize:  String,
    pub prf_alg:        String,
    pub dh_group:       Option<String>,
    pub local_vips:     Vec<String>,
    pub remote_vips:    Vec<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SecurityAssociationLabels {
    pub name: String,
    pub uniqueid: String,
    pub ike_version: u8,
    pub local_id: String,
    pub remote_id: String,
}


impl SecurityAssociationLabels {
    pub async fn set_from_sa(sa: &mut vici::NamedSecurityAssociation) -> Result<SecurityAssociationLabels> {
        let (sa_name, sa_value) = sa;
        Ok(SecurityAssociationLabels {
            name: sa_name,
            uniqueid: sa_value.uniqueid,
            ike_version: sa_value.version,
            local_id: sa_value.local_id.unwrap(),
            remote_id: sa_value.remote_id.unwrap(),
        })
    }
}
