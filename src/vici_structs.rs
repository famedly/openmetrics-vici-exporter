#![allow(dead_code,non_camel_case_types)] // I don't want to be bothered for case stuff decided upon me by the VICI API

use serde::Deserialize;
use std::collections::HashMap;

use futures_util::    stream::StreamExt;

use prometheus_client::encoding::text::Encode;

use anyhow::Result;

#[derive(Debug, Deserialize)]
pub struct VICIState {
    pub version:                Version,
    pub statistics:             Statistics,
    pub policies:               Policies,
    pub connections:            Connections,
    pub security_associations:  SecurityAssociations,
    pub certificates:           Certificates,
    pub authorities:            Authorities,
    pub pools:                  Pools,
}

impl VICIState {
    async fn update(client: &mut rsvici::Client) -> Result<VICIState> {
        Ok(VICIState {
                version:                client.request("version", ()).await?,
                statistics:             client.request("statistics", ()).await?,
                policies:               collected_stream::<NamedPolicy, Policies>(client, "list-policies", "list-policy").await,
                connections:            client.stream_request::<(), Connections>("list-connections", "list-conn", ()).await?,
                security_associations:  client.stream_request::<(), SecurityAssociations>("list-sas", "list-sa", ()).await?,
                certificates:           client.stream_request::<(), Certificates>("list-certs", "list-cert", ()).await?,
                authorities:            client.stream_request::<(), Authorities>("list-authoroties", "list-authoroty", ()).await?,
                pools:                  client.stream_request::<(), Pools>("list-pools", "list-pool", ()).await?,
        })
    }
}

async fn collected_stream<N,C>(client: &mut rsvici::Client, command: &str, event: &str) -> C
where
    N: for<'de> serde::Deserialize<'de>,
    C: std::iter::Extend<N> + Default,
{
    client.stream_request::<(), N>(command, event, ()).filter_map(|event| async move {event.ok()}).collect::<C>().await
}

// Structs for parsing the control interface

#[derive(Debug, Deserialize)]
pub struct Version {
    pub daemon:  String,
    pub version: String,
    pub sysname: String,
    pub release: String,
    pub machine: String,
}

#[derive(Debug, Deserialize)]
pub struct Statistics {
    pub uptime:                   StatisticsUptime,
    pub workers:                  StatisticsWorkers,
    pub queues:                   StatisticsJobPriorities,
    pub scheduled:                String,
    pub ikesecurity_associations: StatisticsIKESecurityAssociations,
    pub plugins:                  Vec<String>,
    pub mem:                      Option<StatisticsMem>,
    pub mallinfo:                 Option<StatisticsMallinfo>,
}

#[derive(Debug, Deserialize)]
pub struct StatisticsUptime {
    pub running: String,
    pub since:   String,
}

#[derive(Debug, Deserialize)]
pub struct StatisticsWorkers {
    pub total:  String,
    pub idle:   String,
    pub active: StatisticsJobPriorities,
}

#[derive(Debug, Deserialize)]
pub struct StatisticsJobPriorities {
    pub critical: String,
    pub high:     String,
    pub medium:   String,
    pub low:      String,
}

#[derive(Debug, Deserialize)]
pub struct StatisticsIKESecurityAssociations {
    pub total:     String,
    pub half_open: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StatisticsMem {
    pub total:  String,
    pub allocs: String,
}
#[derive(Debug, Deserialize)]
pub struct StatisticsMallinfo {
    pub sbrk: String,
    pub mmap: String,
    pub used: String,
    pub free: String,
}

pub type Policies = HashMap<String, Policy>;

pub type NamedPolicy = (String, Policy);

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub child:     String,
    pub ike:       Option<String>,
    pub mode:      PolicyMode,
    pub local_ts:  Option<Vec<String>>,
    pub remote_ts: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
enum PolicyMode {
    tunnel,
    transport,
    pass,
    drop,
}

pub type Connections = HashMap<String, Conn>;

#[derive(Debug, Deserialize)]
pub struct Conn {
    pub local_addrs:  Vec<String>,
    pub remote_addrs: Vec<String>,
    pub version:      String,
    pub reauth_time:  u32,
    pub rekey_time:   u32,
    pub children:     HashMap<String, ConnChildSection>,
}

#[derive(Debug, Deserialize)]
pub struct ConnAuthSection {
    pub class:        String,
    pub eap_type:     Option<String>,
    pub eap_vendor:   Option<String>,
    pub xauth:        Option<String>,
    pub revocation:   Option<String>,
    pub id:           String,
    pub aaa_id:       Option<String>,
    pub eap_id:       Option<String>,
    pub xauth_id:     Option<String>,
    pub groups:       Option<Vec<String>>,
    pub certificates: Option<Vec<String>>,
    pub cacerts:      Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ConnChildSection {
    pub mode:          ChildSecurityAssociationMode,
    pub rekey_time:    u32,
    pub rekey_bytes:   u64,
    pub rekey_packets: u64,
    pub local_ts:      Option<Vec<String>>,
    pub remote_ts:     Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, Hash, PartialEq, Eq)]
enum ChildSecurityAssociationMode {
    TUNNEL,
    TRANSPORT,
    BEET,
}
#[derive(Debug, Deserialize, Clone, Hash, PartialEq, Eq)]
enum ChildSecurityAssociationProtocol {
    AH,
    ESP,
}

pub type SecurityAssociations = HashMap<String, SecurityAssociation>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecurityAssociation {
    pub uniqueid:                    String,
    pub version:                     u8,
    pub state:                       String,
    pub local_host:                  Option<String>,
    pub local_port:                  Option<u16>,
    pub local_id:                    Option<String>,
    pub remote_host:                 Option<String>,
    pub remote_port:                 Option<u16>,
    pub remote_id:                   Option<String>,
    pub remote_xauth_id:             Option<String>,
    pub remote_epa_id:               Option<String>,
    pub initiator:                   Option<bool>,
    pub initiator_spi:               Option<String>,
    pub responder_spi:               Option<String>,
    pub nat_local:                   Option<bool>,
    pub nat_remote:                  Option<bool>,
    pub nat_fake:                    Option<bool>,
    pub nat_any:                     Option<bool>,
    pub if_id_in:                    Option<String>,
    pub if_id_out:                   Option<String>,
    pub encr_alg:                    Option<String>,
    pub encr_keysize:                Option<String>,
    pub integ_alg:                   Option<String>,
    pub integ_keysize:               Option<String>,
    pub prf_alg:                     Option<String>,
    pub dh_group:                    Option<String>,
    pub established:                 u64,
    pub rekey_time:                  Option<u32>,
    pub reauth_time:                 Option<u32>,
    pub local_vips:                  Option<Vec<String>>,
    pub remote_vips:                 Option<Vec<String>>,
    pub tasks_queued:                Option<Vec<String>>,
    pub tasks_active:                Option<Vec<String>>,
    pub tasks_passive:               Option<Vec<String>>,
    pub child_security_associations: Option<HashMap<String, SecurityAssociationChild>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecurityAssociationChild {
    pub name:           String,
    pub uniqueid:       String,
    pub reqid:          String,
    pub state:          String,
    pub mode:           ChildSecurityAssociationMode,
    pub protocol:       ChildSecurityAssociationProtocol,
    pub encap:          Option<bool>,
    pub spi_in:         String,
    pub spi_out:        String,
    pub cpi_in:         Option<String>,
    pub cpi_out:        Option<String>,
    pub mark_in:        Option<String>,
    pub mark_mask_in:   Option<String>,
    pub mark_out:       Option<String>,
    pub mark_mask_out:  Option<String>,
    pub if_id_in:       Option<String>,
    pub if_id_out:      Option<String>,
    pub encr_alg:       Option<String>,
    pub encr_keysize:   Option<String>,
    pub integ_alg:      Option<String>,
    pub integ_keysize:  Option<String>,
    pub prf_alg:        Option<String>,
    pub dh_group:       Option<String>,
    pub esn:            Option<u16>,
    pub bytes_in:       u64,
    pub packets_in:     u64,
    pub use_in:         Option<u32>,
    pub bytes_out:      u64,
    pub packets_out:    u64,
    pub use_out:        Option<u32>,
    pub rekey_time:     Option<u32>,
    pub life_time:      u32,
    pub install_time:   u64,
    pub local_ts:       Vec<String>,
    pub remote_ts:      Vec<String>,
}

pub type Certificates = HashMap<String, Cert>;

#[derive(Debug, Deserialize)]
pub struct Cert {
    pub r#type: CertType,
    pub flag:        X509CertFlag,
    pub has_privkey: Option<String>,
    pub data:        String,
    pub subject:     Option<String>,
    pub not_before:  Option<String>,
    pub not_after:   Option<String>,
}

#[derive(Debug, Deserialize)]
enum CertType {
    X509,
    X509_AC,
    X509_CRL,
    OSCP_RESPONSE,
    PUBKEY,
}

#[derive(Debug, Deserialize)]
enum X509CertFlag {
    NONE,
    CA,
    AA,
    OCSP,
}

pub type Authorities = HashMap<String, Authority>;

#[derive(Debug, Deserialize)]
pub struct Authority {
    pub cacert:         String,
    pub crl_uris:       Vec<String>,
    pub ocsp_uris:      Vec<String>,
    pub cert_uri_base:  String,
}

pub type Pools = HashMap<String, Pool>;

#[derive(Debug,Deserialize)]
pub struct Pool {
    pub name:    String,
    pub base:    String,
    pub size:    u128,
    pub online:  u128,
    pub offline: u128,
    pub leases:  Option<HashMap<u16,PoolLease>>,
}

#[derive(Debug,Deserialize)]
pub struct PoolLease {
    pub address:  String,
    pub identity: String,
    pub status:   PoolLeaseStatus,
}

#[derive(Debug, Deserialize)]
enum PoolLeaseStatus {
    online,
    offline,
}

// Structs for generating metrics, TODO

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

#[derive(Debug, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct SecurityAssociationChildInfo {
    pub name:           String,
    pub uniqueid:       String,
    pub reqid:          String,
    pub mode:           ChildSecurityAssociationMode,
    pub if_id_in:       String,
    pub if_id_out:      String,
    pub encr_alg:       String,
    pub encr_keysize:   String,
    pub integ_alg:      String,
    pub integ_keysize:  String,
    pub prf_alg:        String,
    pub dh_group:       Option<String>,
    pub local_ts:       Vec<String>,
    pub remote_ts:      Vec<String>,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub struct SecurityAssociationLabels {
    pub uniqueid: String,
}
