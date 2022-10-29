use crate::radius_packet::RadiusPacket;

pub trait PacketHandler {
    fn handle_packet(&self, packet: RadiusPacket, secret_bytes: &[u8]) -> Option<RadiusPacket>;
}
