//! `hanzo-zap-mdns` — mDNS publish + browse for Hanzo services per HIP-0069.
//!
//! Single source of truth for the service-type, TXT key list, and role enum
//! across every Rust service in the Hanzo stack (`hanzo-engine`, `hanzo-node`).
//!
//! # Example
//!
//! ```no_run
//! use zap_mdns::{Publisher, PublishOptions, Role};
//!
//! let pub_ = Publisher::publish(PublishOptions {
//!     role: Role::Engine,
//!     port: 8000,
//!     version: env!("CARGO_PKG_VERSION").into(),
//!     capabilities: vec!["completion".into(), "embed".into()],
//!     ..Default::default()
//! }).expect("mdns publish");
//! // …keep `pub_` alive for the service's lifetime; `Drop` retracts the record.
//! ```

use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// Canonical mDNS service-type for the Hanzo mesh.
pub const SERVICE_TYPE: &str = "_hanzo._tcp.local.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Mcp,
    Iam,
    Kms,
    Mpc,
    Base,
    Engine,
    Browser,
    Node,
    Desktop,
    Gateway,
    Static,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Mcp => "mcp",
            Role::Iam => "iam",
            Role::Kms => "kms",
            Role::Mpc => "mpc",
            Role::Base => "base",
            Role::Engine => "engine",
            Role::Browser => "browser",
            Role::Node => "node",
            Role::Desktop => "desktop",
            Role::Gateway => "gateway",
            Role::Static => "static",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "mcp" => Role::Mcp,
            "iam" => Role::Iam,
            "kms" => Role::Kms,
            "mpc" => Role::Mpc,
            "base" => Role::Base,
            "engine" => Role::Engine,
            "browser" => Role::Browser,
            "node" => Role::Node,
            "desktop" => Role::Desktop,
            "gateway" => Role::Gateway,
            "static" => Role::Static,
            _ => return None,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("mdns: {0}")]
    Mdns(#[from] mdns_sd::Error),
    #[error("hostname: {0}")]
    Hostname(#[from] std::io::Error),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    pub role: Option<Role>,
    pub port: u16,
    pub server_id: Option<String>,
    pub org: Option<String>,
    pub version: String,
    pub proto: Option<String>,           // default "zap/1"
    pub capabilities: Vec<String>,
    pub agent_label: Option<String>,
    pub auth: Option<String>,            // "none" | "iam" | "mtls"
    pub host: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HanzoService {
    pub role: Role,
    pub server_id: String,
    pub org: String,
    pub version: String,
    pub proto: String,
    pub capabilities: Vec<String>,
    pub agent_label: String,
    pub auth: String,
    pub host: String,
    pub port: u16,
}

impl HanzoService {
    pub fn url(&self) -> String {
        let scheme = if self.proto.starts_with("http") {
            "http"
        } else {
            "ws"
        };
        format!("{scheme}://{}:{}/", self.host, self.port)
    }
}

/// RAII handle: dropping the publisher retracts the mDNS announcement.
pub struct Publisher {
    daemon: ServiceDaemon,
    full_name: String,
}

impl Publisher {
    /// Advertise a service on the LAN. Holding the returned `Publisher`
    /// alive is what keeps the announcement live; `Drop` retracts it.
    pub fn publish(opts: PublishOptions) -> Result<Self, Error> {
        let role = opts.role.ok_or(Error::MissingField("role"))?;
        if opts.port == 0 {
            return Err(Error::MissingField("port"));
        }
        if opts.version.is_empty() {
            return Err(Error::MissingField("version"));
        }
        let host = opts
            .host
            .clone()
            .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
            .unwrap_or_else(|| "localhost".to_string());
        let server_id = opts
            .server_id
            .clone()
            .unwrap_or_else(|| format!("{}-{}-{}", role.as_str(), host, std::process::id()));
        let org = opts.org.clone().unwrap_or_else(|| "hanzo".to_string());
        let proto = opts.proto.clone().unwrap_or_else(|| "zap/1".to_string());
        let auth = opts.auth.clone().unwrap_or_else(|| "none".to_string());
        let mut props = HashMap::new();
        props.insert("role".to_string(), role.as_str().to_string());
        props.insert("server_id".to_string(), server_id.clone());
        props.insert("org".to_string(), org);
        props.insert("version".to_string(), opts.version.clone());
        props.insert("proto".to_string(), proto);
        props.insert("capabilities".to_string(), opts.capabilities.join(","));
        props.insert("auth".to_string(), auth);
        if let Some(label) = opts.agent_label.clone() {
            props.insert("agent_label".to_string(), label);
        }

        let daemon = ServiceDaemon::new()?;
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &server_id,
            &format!("{server_id}.local."),
            "",
            opts.port,
            Some(props),
        )?
        .enable_addr_auto();

        let full_name = info.get_fullname().to_string();
        daemon.register(info)?;
        Ok(Self { daemon, full_name })
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.full_name);
        let _ = self.daemon.shutdown();
    }
}

/// Browse the LAN for Hanzo services. `role` filter is optional (None → all).
pub fn browse(role: Option<Role>, timeout: Duration) -> Result<Vec<HanzoService>, Error> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse(SERVICE_TYPE)?;
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                if let Some(svc) = parse_service(&info) {
                    if let Some(want) = role {
                        if svc.role != want {
                            continue;
                        }
                    }
                    out.push(svc);
                }
            }
            Ok(_) => continue, // ServiceFound, ServiceRemoved, etc.
            Err(_) => break,   // timeout or channel closed
        }
    }
    let _ = daemon.shutdown();
    Ok(out)
}

fn parse_service(info: &mdns_sd::ServiceInfo) -> Option<HanzoService> {
    let props = info.get_properties();
    let role_str = props.get("role")?.val_str();
    let role = Role::from_str(role_str)?;
    let host = info
        .get_addresses_v4()
        .iter()
        .next()
        .map(|a| a.to_string())
        .unwrap_or_else(|| info.get_hostname().trim_end_matches('.').to_string());
    Some(HanzoService {
        role,
        server_id: props
            .get("server_id")
            .map(|p| p.val_str().to_string())
            .unwrap_or_else(|| info.get_fullname().to_string()),
        org: props.get("org").map(|p| p.val_str().to_string()).unwrap_or_else(|| "hanzo".into()),
        version: props.get("version").map(|p| p.val_str().to_string()).unwrap_or_default(),
        proto: props.get("proto").map(|p| p.val_str().to_string()).unwrap_or_else(|| "zap/1".into()),
        capabilities: props
            .get("capabilities")
            .map(|p| {
                p.val_str()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default(),
        agent_label: props.get("agent_label").map(|p| p.val_str().to_string()).unwrap_or_default(),
        auth: props.get("auth").map(|p| p.val_str().to_string()).unwrap_or_else(|| "none".into()),
        host,
        port: info.get_port(),
    })
}
