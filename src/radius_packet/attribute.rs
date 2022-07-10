pub struct Attribute {
    pub identifier: u8,
    pub packetcode: packet_codes::PacketCode,
    pub authenticator: [u8; 16],
    pub request_authenticator: [u8; 16],
}