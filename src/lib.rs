use core::fmt;
use std::net::SocketAddr;

use base64::Engine;
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};

pub mod utils;

const LABEL_MAC1: &'static str = "mac1----";

#[derive(Clone, Debug)]
pub struct Peer {
    pub pub_key: [u8; 32],                     // TODO: is this the right length?
    pub precomputed_hash_label_mac1: [u8; 32], // used as key for mac1 function
    pub address: SocketAddr,
}

impl<'de> Deserialize<'de> for Peer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            PubKey,
            Address,
        }

        struct PeerVisitor;

        impl<'de> Visitor<'de> for PeerVisitor {
            type Value = Peer;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Peer")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Peer, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let address = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let pubkey = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                Ok(Peer::build(address, pubkey))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Peer, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut address = None;
                let mut pubkey = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PubKey => {
                            if pubkey.is_some() {
                                return Err(de::Error::duplicate_field("pubkey"));
                            }
                            pubkey = Some(map.next_value()?);
                        }
                        Field::Address => {
                            if address.is_some() {
                                return Err(de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?);
                        }
                    }
                }
                let address = address.ok_or_else(|| de::Error::missing_field("address"))?;
                let pubkey = pubkey.ok_or_else(|| de::Error::missing_field("pubkey"))?;
                Ok(Peer::build(address, pubkey))
            }
        }
        const FIELDS: &[&str] = &["address", "pubkey"];
        deserializer.deserialize_struct("Peer", FIELDS, PeerVisitor)
    }
}

impl Peer {
    pub fn build(address: String, pub_key: String) -> Self {
        let address = address.parse::<std::net::SocketAddr>().unwrap();
        let pub_key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(pub_key)
            .unwrap()
            .try_into()
            .unwrap();
        let hash = blake2s_simd::Params::new()
            .to_state()
            .update(LABEL_MAC1.as_bytes())
            .update(pub_key.as_slice())
            .finalize()
            .as_array()
            .to_owned();

        Peer {
            pub_key,
            precomputed_hash_label_mac1: hash,
            address,
        }
    }
}
