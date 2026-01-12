use std::io;
use std::sync::mpsc::Receiver;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use notify::Event;
use rkyv::rancor::Failure;
use rkyv::{Archive, Deserialize, Portable};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::debug;
use wireguard_router::utils;
use wireguard_router::{Peer, utils::is_wg_packet};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::state::Identity;

#[derive(FromBytes, KnownLayout, Immutable, Unaligned, Debug, PartialEq)]
#[repr(C)]
pub struct HandshakeInitiation {
    r#type: u8,
    reserved: [u8; 3],
    sender: Identity,
    ephemeral: [u8; 32],
    r#static: [u8; 48],
    timestamp: [u8; 28],
    mac1: [u8; 16],
    mac2: [u8; 16],
}
#[derive(FromBytes, KnownLayout, Immutable, Unaligned, Debug, PartialEq)]
#[repr(C)]
pub struct HandshakeResponse {
    r#type: u8,
    reserved: [u8; 3],
    sender: Identity,
    receiver: Identity,
    ephemeral: [u8; 32],
    empty: [u8; 16],
    mac1: [u8; 16],
    mac2: [u8; 16],
}
#[derive(FromBytes, KnownLayout, Immutable, Unaligned, Debug, PartialEq)]
#[repr(C)]
pub struct CookieReply {
    r#type: u8,
    reserved: [u8; 3],
    receiver: Identity,
    nonce: [u8; 24],
    cookie: [u8; 32],
}
#[derive(FromBytes, KnownLayout, Immutable, Unaligned, Debug, PartialEq)]
#[repr(C)]
pub struct TransportDataHeader {
    r#type: u8,
    reserved: [u8; 3],
    receiver: Identity,
    counter: [u8; 8],
}

pub enum WireguardPacket<'a> {
    HandshakeInitiation(&'a HandshakeInitiation),
    HandshakeResponse(&'a HandshakeResponse),
    CookieReply(&'a CookieReply),
    TransportData((&'a TransportDataHeader, &'a [u8], usize)),
}

impl<'a> TryFrom<(&'a [u8], usize)> for WireguardPacket<'a> {
    type Error = crate::error::Error;

    fn try_from((data, size): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        match (data[0], size) {
            (0x01, 148) => Ok(WireguardPacket::HandshakeInitiation(
                HandshakeInitiation::ref_from_bytes(&data[..148]).unwrap(),
            )),
            (0x02, 92) => Ok(WireguardPacket::HandshakeResponse(
                HandshakeResponse::ref_from_bytes(&data[..92]).unwrap(),
            )),
            (0x03, 64) => Ok(WireguardPacket::CookieReply(
                CookieReply::ref_from_bytes(&data[..64]).unwrap(),
            )),
            (0x04, 32..usize::MAX) => Ok(WireguardPacket::TransportData((
                // cast header
                TransportDataHeader::ref_from_bytes(&data[..16]).unwrap(),
                // rest of the packet (data)
                &data[16..size],
                // size of data (packet size - header)
                size - 16,
            ))),
            _ => Err(crate::error::Error::InvalidPacket),
        }
    }
}

pub struct Router {
    socket: UdpSocket,
    to_process: Option<(usize, SocketAddr)>,
    config_rx: Receiver<Result<Event, notify::Error>>,
    peers: Vec<Peer>,
    /// Identity -> (From, To)
    sessions: Arc<Mutex<HashMap<Identity, (SocketAddr, SocketAddr)>>>,
}

impl Router {
    pub fn new(socket: UdpSocket, config_rx: Receiver<Result<Event, notify::Error>>) -> Self {
        let peers = crate::config::settings().read().unwrap().peers.to_owned();
        tracing::info!("loaded {} peers", peers.len());
        Router {
            socket,
            to_process: None,
            config_rx,
            peers,
            sessions: Default::default(),
        }
    }

    async fn handle_packet(&self, size: usize, peer: SocketAddr, data: &[u8]) {
        if !is_wg_packet(size, &data) {
            return;
        }

        let sessions = self.sessions.to_owned();

        match WireguardPacket::try_from((data, size)) {
            Ok(packet) => match packet {
                WireguardPacket::HandshakeInitiation(packet) => {
                    // tracing::trace!("processing initiation packet {:?}", packet);
                    let mut sessions = sessions.lock().await;
                    match sessions.get(&packet.sender).cloned() {
                        Some(session) => {
                            let _ = self.socket.send_to(&data[..size], session.1).await;
                        }
                        None => match self.peers.iter().find(|p| {
                            let peer_mac =
                                utils::mac(p.precomputed_hash_label_mac1.as_slice(), &data[..116]);
                            tracing::trace!(
                                "comparing {:?} to peer {:?}",
                                &packet.mac1.as_slice(),
                                &peer_mac
                            );
                            &packet.mac1 == &peer_mac
                        }) {
                            Some(backend) => {
                                tracing::trace!("found backend with address {}", backend.address);
                                sessions.insert(packet.sender, (peer, backend.address));
                                tracing::trace!("forwarding");
                                let _ = self.socket.send_to(&data[..size], backend.address).await;
                            }
                            None => debug!("dropping packet to unknown backend"),
                        },
                    }
                }
                WireguardPacket::HandshakeResponse(packet) => {
                    let mut sessions = sessions.lock().await;
                    match sessions.get(&packet.receiver).cloned() {
                        Some(session) => {
                            sessions.insert(packet.sender, (peer, session.0));
                            let _ = self.socket.send_to(&data[..size], session.0).await;
                        }
                        None => debug!("dropping response packet, no matching session"),
                    }
                }
                WireguardPacket::CookieReply(packet) => {
                    let sessions = sessions.lock().await;
                    match sessions.get(&packet.receiver) {
                        Some((client, _)) => {
                            let _ = self.socket.send_to(&data[..size], client).await;
                        }
                        None => debug!("dropping cookie packet, no matching session"),
                    }
                }
                WireguardPacket::TransportData((header, _, _)) => {
                    let sessions = sessions.lock().await;
                    match sessions.get(&header.receiver) {
                        Some(session) => {
                            let _ = self.socket.send_to(&data[..size], session.1).await;
                        }
                        None => {}
                    }
                }
            },
            Err(err) => debug!(
                "dropping invalid packet with size {} of type {}: {}",
                size, data[0], err
            ),
        }
    }

    pub async fn run(mut self) -> Result<(), io::Error> {
        // TODO:
        // refresh peers based on config
        // then trigger a GC for sessions

        // lets just use a 70kb buffer
        let mut buf: Vec<u8> = vec![0; 1024 * 70];

        loop {
            if let Some((size, peer)) = self.to_process {
                self.handle_packet(size, peer, &buf).await;
            }

            tracing::trace!("waiting for next packet");
            self.to_process = Some(self.socket.recv_from(&mut buf).await?);
        }
    }
}
