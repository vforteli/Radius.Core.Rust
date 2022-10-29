use crate::{
    packet_handler::PacketHandler,
    radius_packet::{
        packet_codes::PacketCode, radius_password::decrypt, rfc_attribute_type::RfcAttributeType,
        RadiusPacket,
    },
};

pub struct TestPacketHandler {}

impl PacketHandler for TestPacketHandler {
    fn handle_packet(&self, packet: RadiusPacket, secret_bytes: &[u8]) -> Option<RadiusPacket> {
        let response_packet = match packet.packetcode {
            PacketCode::AccessRequest => {
                // yes yes, this should be done in one go...
                let username = packet.attributes.iter().find_map(|a| match a {
                    RfcAttributeType::UserName(u) => Some(u),
                    _ => None,
                });

                let password = packet.attributes.iter().find_map(|a| match a {
                    RfcAttributeType::UserPassword(u) => {
                        Some(decrypt(secret_bytes, &packet.authenticator, u))
                    }
                    _ => None,
                });

                println!("Username {:?}, password {:?}", username, password);

                let response_packet_code =
                    if username.unwrap() == "watho" && password.unwrap().unwrap() == "sup" {
                        PacketCode::AccessAccept
                    } else {
                        PacketCode::AccessReject
                    };

                Some(RadiusPacket::new_response(
                    response_packet_code,
                    packet.identifier,
                    packet.authenticator,
                ))
            }
            _ => None,
        };

        response_packet
    }
}
