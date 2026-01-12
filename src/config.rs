use std::sync::{OnceLock, RwLock};

use config::File;
use serde::Deserialize;
use wireguard_router::Peer;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub peers: Vec<Peer>,
}

pub fn settings() -> &'static RwLock<Config> {
    static CONFIG: OnceLock<RwLock<Config>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let settings = load();

        RwLock::new(settings)
    })
}

fn refresh() {
    *settings().write().unwrap() = load();
}

fn load() -> Config {
    config::Config::builder()
        .add_source(File::with_name("config.toml"))
        .build()
        .unwrap()
        .try_deserialize::<Config>()
        .unwrap()
}

fn show() {
    println!(
        " * Settings :: \n\x1b[31m{:?}\x1b[0m",
        settings().read().unwrap()
    );
}
