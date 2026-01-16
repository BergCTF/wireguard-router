/*
* state.rs contains shared state between the api server and the router
*/

use std::sync::Arc;

use tokio::sync::Mutex;
use wireguard_router::Peer;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Clone, Debug, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Identity(pub [u8; 4]);

impl From<[u8; 4]> for Identity {
    fn from(value: [u8; 4]) -> Self {
        Self(value)
    }
}

#[derive(Clone)]
pub struct State {
    pub peers: Arc<Mutex<Vec<Peer>>>,
}
