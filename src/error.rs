use thiserror::Error;

#[derive(Clone, Error, Debug)]
pub enum Error {
    #[error("Packet too short")]
    PacketTooShort,
    #[error("Invalid Packet")]
    InvalidPacket,
}
