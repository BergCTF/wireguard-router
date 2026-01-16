use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::env;
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::router::Router;

pub mod config;
pub mod error;
pub mod router;
pub mod state;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:51337".to_string());

    let socket = UdpSocket::bind(&addr).await?;
    tracing::info!("Listening on: {}", socket.local_addr()?);

    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(
        tx,
        notify::Config::default().with_poll_interval(Duration::from_secs(2)),
    )
    .unwrap();

    watcher
        .watch(Path::new("config.toml"), RecursiveMode::NonRecursive)
        .unwrap();

    let router = Router::new(socket);
    router.run(rx).await?;

    Ok(())
}
