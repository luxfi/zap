//! Example: what a Rust service does on startup. Run with
//! `cargo run --example publish_kms`.
use zap_mdns::{Publisher, PublishOptions, Role};
use std::time::Duration;

fn main() -> Result<(), zap_mdns::Error> {
    let _pub = Publisher::publish(PublishOptions {
        role: Some(Role::Kms),
        port: 8443,
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec!["sign".into(), "verify".into(), "encrypt".into(), "decrypt".into()],
        auth: Some("iam".into()),
        ..Default::default()
    })?;
    println!("published; sleeping 60s. dns-sd -B _hanzo._tcp local. to verify.");
    std::thread::sleep(Duration::from_secs(60));
    Ok(())
}
