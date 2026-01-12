use blake2s_simd::Hash;

/// Blake2s(input, 32), returning 32 bytes of output
pub fn hash(input: &[u8]) -> [u8; 32] {
    hash_raw(input).as_array().to_owned()
}

pub fn hash_raw(input: &[u8]) -> Hash {
    blake2s_simd::blake2s(input)
}

/// Keyed-Blake2s(key, input, 16), the keyed MAC variant of the BLAKE2s hash function, returning 16 bytes of output
pub fn mac(key: &[u8], input: &[u8]) -> [u8; 16] {
    blake2s_simd::Params::new()
        .hash_length(16)
        .key(key)
        .hash(input)
        .as_bytes()
        .try_into()
        .unwrap()
}

/// heuristics taken from https://wiki.wireshark.org/WireGuard
/// It tests the first byte for a valid message type (1, 2, 3, or 4) and checks that the next three reserved bytes are zero.
pub fn is_wg_packet(size: usize, packet: &[u8]) -> bool {
    size > 4
        && 0x01 <= packet[0]
        && packet[0] <= 0x04
        && (packet[1] | packet[2] | packet[3]) == 0x00
}
