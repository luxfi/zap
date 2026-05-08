//! Example: browse every Hanzo service on the LAN. Run with
//! `cargo run --example browse_all`.
use zap_mdns::{browse};
use std::time::Duration;

fn main() -> Result<(), zap_mdns::Error> {
    let services = browse(None, Duration::from_secs(2))?;
    println!("found {} services:", services.len());
    for s in services {
        println!("  {:8} {:32} {:32} caps={:?}",
            s.role.as_str(), s.server_id, s.url(), s.capabilities);
    }
    Ok(())
}
