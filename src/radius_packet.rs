use byteorder::{BigEndian, ByteOrder};
use rand::Rng;

use self::{rfc_attribute_type::RfcAttributeType, rfc_attribute_value::RfcAttributeValue};

pub mod packet_codes;
pub mod packet_parsing_error;
pub mod radius_password;
pub mod rfc_attribute_type;
pub mod rfc_attribute_value;
pub mod utils;

const PACKET_HEADER_SIZE: usize = 4;
const AUTHENTICATOR_SIZE: usize = 16;

type Authenticator = [u8; 16];

pub struct RadiusPacket {
    pub identifier: u8,
    pub packetcode: packet_codes::PacketCode,
    pub authenticator: Authenticator,
    pub request_authenticator: Authenticator,
    pub attributes: Vec<RfcAttributeType>,
}

impl RadiusPacket {
    pub fn new_response(
        packetcode: packet_codes::PacketCode,
        identifier: u8,
        request_authenticator: Authenticator,
    ) -> Self {
        Self {
            packetcode,
            identifier,
            authenticator: [0; AUTHENTICATOR_SIZE],
            request_authenticator,
            attributes: Vec::new(),
        }
    }

    pub fn new_request(packetcode: packet_codes::PacketCode, identifier: u8) -> Self {
        Self {
            packetcode,
            identifier,
            authenticator: rand::thread_rng().gen::<Authenticator>(),
            request_authenticator: [0; AUTHENTICATOR_SIZE],
            attributes: Vec::new(),
        }
    }

    pub fn get_bytes(self, secret_bytes: &[u8]) -> Vec<u8> {
        let mut header_bytes: [u8; PACKET_HEADER_SIZE] =
            [self.packetcode as u8, self.identifier, 0, 0];

        let mut message_authenticator_position: usize = 0;
        let mut attribute_bytes: Vec<u8> = Vec::new();

        for attribute in self.attributes {
            println!("adding attribute {:?}", attribute);

            let attribute: RfcAttributeValue = attribute.into();

            // message authenticator position is saved since we have to calculate and populate this after everything else
            if attribute.code == 80 {
                message_authenticator_position = attribute_bytes.len();
            }

            println!(
                "adding attribute {} : {:?}",
                attribute.code, attribute.value
            );
            attribute_bytes.extend([attribute.code]);
            attribute_bytes.extend([(attribute.value.len() as u8) + 2]);
            attribute_bytes.extend(attribute.value);
        }

        let packet_length_bytes = PACKET_HEADER_SIZE + AUTHENTICATOR_SIZE + attribute_bytes.len(); // header + authenticator + attributes

        BigEndian::write_u16(
            &mut header_bytes[2..4],
            packet_length_bytes.try_into().unwrap(),
        );

        let authenticator_bytes = match self.packetcode {
            packet_codes::PacketCode::StatusServer => {
                let message_authenticator =
                    utils::calculate_message_authenticator_for_access_reject_etc(
                        &header_bytes,
                        &self.authenticator,
                        &attribute_bytes,
                        secret_bytes,
                    );

                attribute_bytes.splice(message_authenticator_position + 2.., message_authenticator);

                self.authenticator
            }
            _ => {
                if message_authenticator_position != 0 {
                    let message_authenticator =
                        utils::calculate_message_authenticator_for_access_reject_etc(
                            &header_bytes,
                            &self.request_authenticator,
                            &attribute_bytes,
                            secret_bytes,
                        );
                    attribute_bytes
                        .splice(message_authenticator_position + 2.., message_authenticator);
                }

                // todo ooooh boy.. fix this
                let authenticator_bytes: Authenticator = match self.packetcode {
                    packet_codes::PacketCode::AccessRequest => self.authenticator,
                    _ => utils::calculate_response_authenticator(
                        &header_bytes,
                        &self.request_authenticator,
                        &attribute_bytes,
                        secret_bytes,
                    ),
                };

                authenticator_bytes
            }
        };

        let mut response_packet_bytes: Vec<u8> = Vec::new();
        response_packet_bytes.extend(header_bytes);
        response_packet_bytes.extend(authenticator_bytes);
        response_packet_bytes.extend(attribute_bytes);

        return response_packet_bytes;
    }

    pub fn parse(
        packet_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> Result<Self, packet_parsing_error::PacketParsingError> {
        let length_from_packet = BigEndian::read_u16(&packet_bytes[2..4]) as usize;

        if packet_bytes.len() < length_from_packet.into() {
            return Err(packet_parsing_error::PacketParsingError::InvalidLength);
        }

        let packet_bytes = &packet_bytes[0..length_from_packet];

        let mut packet = Self {
            identifier: packet_bytes[1],
            packetcode: packet_codes::PacketCode::from(packet_bytes[0]),
            authenticator: packet_bytes[4..20].try_into().unwrap(),
            request_authenticator: [0; 16],
            attributes: Vec::new(),
        };

        println!(
            "Parsing {:?} packet with id {}",
            packet.packetcode, packet.identifier
        );

        if (packet.packetcode == packet_codes::PacketCode::AccountingRequest
            || packet.packetcode == packet_codes::PacketCode::DisconnectRequest)
            && utils::calculate_request_authenticator(
                &packet_bytes[0..PACKET_HEADER_SIZE].try_into().unwrap(),
                &packet_bytes[20..],
                secret_bytes,
            ) != packet.authenticator
        {
            return Err(packet_parsing_error::PacketParsingError::InvalidRequestAuthenticator);
        }

        // The rest are attribute value pairs
        let mut position: usize = 20;
        let mut message_authenticator_position: usize = 0;

        while position < length_from_packet {
            let typecode = &packet_bytes[position];
            let attribute_length = packet_bytes[(position + 1)] as usize;
            let attribute_content_length = attribute_length - 2;
            let attribute_content_bytes =
                &packet_bytes[position + 2..position + 2 + attribute_content_length];

            // Vendor specific attribute
            if *typecode == 26 {
                // do some parsing eh
            } else {
                if *typecode == 80 {
                    message_authenticator_position = position; // have to save the position to be able to zero it when validating the packet
                }

                println!("Attribute {} : {:?}", typecode, attribute_content_bytes);
                packet.attributes.push(
                    RfcAttributeValue {
                        code: typecode.to_owned(),
                        value: attribute_content_bytes.to_vec(),
                    }
                    .into(),
                );
            }

            position += attribute_length;
        }

        // validate message authenticator if one is found
        // actually this should also require a message authenticator for certain packet types
        if message_authenticator_position != 0 {
            println!("Found message authenticator!");
            let calculated_message_authenticator = utils::calculate_message_authenticator(
                packet_bytes,
                secret_bytes,
                message_authenticator_position,
                None,
            );

            let expected_message_authenticator = &packet_bytes
                [message_authenticator_position + 2..message_authenticator_position + 2 + 16];

            if expected_message_authenticator != calculated_message_authenticator {
                return Err(packet_parsing_error::PacketParsingError::InvalidMessageAuthenticator);
            }
        }

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parse_packet_valid_message_authenticator() {
        let secret = "xyzzy5461".as_bytes();
        let test_packet_bytes = hex::decode(
            "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3",
        )
        .unwrap();

        let packet = RadiusPacket::parse(&test_packet_bytes, secret);

        assert!(packet.is_ok())
    }

    #[test]
    fn parse_packet_invalid_message_authenticator() {
        let secret = "xyzzy5461durr".as_bytes();
        let test_packet_bytes = hex::decode(
            "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3",
        )
        .unwrap();

        let packet = RadiusPacket::parse(&test_packet_bytes, secret);

        assert!(packet.is_err())
    }

    #[test]
    fn parse_packet_valid_request_authenticator() {
        let secret = "xyzzy5461".as_bytes();
        let test_packet_bytes = hex::decode(
            "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234",
        )
        .unwrap();

        let packet = RadiusPacket::parse(&test_packet_bytes, secret);

        assert!(packet.is_ok())
    }

    #[test]
    fn parse_packet_invalid_request_authenticator() {
        let secret = "foo".as_bytes();
        let test_packet_bytes = hex::decode(
            "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234",
        )
        .unwrap();

        let packet = RadiusPacket::parse(&test_packet_bytes, secret);

        assert!(packet.is_err())
    }

    #[test]
    fn parse_and_assemble_packet() {
        let secret = "xyzzy5461".as_bytes();
        let test_packet_bytes = hex::decode(
            "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234",
        )
        .unwrap();

        let packet = RadiusPacket::parse(&test_packet_bytes, secret);

        let packet_bytes = packet.unwrap().get_bytes(secret);

        assert_eq!(test_packet_bytes, packet_bytes);
    }

    #[test]
    fn parse_and_assemble_packet_extra_bytes() {
        let secret = "xyzzy5461".as_bytes();
        let test_packet_bytes = hex::decode(
            "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234ff00ff00ff00ff",
        )
        .unwrap();

        let expected_bytes = hex::decode(
            "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234",
        )
        .unwrap();

        let packet = RadiusPacket::parse(&test_packet_bytes, secret);

        let actual_packet_bytes = packet.unwrap().get_bytes(secret);

        assert_eq!(expected_bytes, actual_packet_bytes);
    }

    #[test]
    fn parse_and_assemble_packet_missing_bytes() {
        let secret = "xyzzy5461".as_bytes();
        let test_packet_bytes = hex::decode(
            "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c0732303032",
        )
        .unwrap();

        let packet = RadiusPacket::parse(&test_packet_bytes, secret);

        assert!(packet.is_err())
    }

    #[test]
    fn create_access_request_packet() {
        let secret_bytes = "xyzzy5461".as_bytes();
        let expected_bytes = hex::decode("010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee0406c0a80110050600000003").unwrap();

        let mut packet =
            RadiusPacket::new_request(super::packet_codes::PacketCode::AccessRequest, 0);

        // setting this manually here to match expected bytes... it is actually random
        // packet.authenticator = hex::decode("00000000000000000000000000000000")
        packet.authenticator = hex::decode("0f403f9473978057bd83d5cb98f4227a")
            .unwrap()
            .try_into()
            .unwrap();

        packet
            .attributes
            .push(RfcAttributeType::UserName("nemo".to_string()));
        packet
            .attributes
            .push(RfcAttributeType::UserPassword(radius_password::encrypt(
                secret_bytes,
                &packet.authenticator,
                "arctangent".as_bytes(),
            )));
        packet
            .attributes
            .push(RfcAttributeType::NasIpAddress(Ipv4Addr::new(
                192, 168, 1, 16,
            )));
        packet.attributes.push(RfcAttributeType::NASPort(3));

        let packet_bytes = packet.get_bytes(secret_bytes);

        assert_eq!(expected_bytes, packet_bytes);
    }

    #[test]
    fn create_coa_request_packet() {
        let secret_bytes = "xyzzy5461".as_bytes();
        let expected_bytes = hex::decode(
            "2b0000266613591d86e32fa6dbae94f13772573601066e656d6f0406c0a80110050600000003",
        )
        .unwrap();

        let mut packet = RadiusPacket::new_request(super::packet_codes::PacketCode::CoaRequest, 0);

        // setting this manually here to match expected bytes... it is actually random
        packet.authenticator = hex::decode("0f403f9473978057bd83d5cb98f4227a")
            .unwrap()
            .try_into()
            .unwrap();

        packet
            .attributes
            .push(RfcAttributeType::UserName("nemo".to_string()));

        packet
            .attributes
            .push(RfcAttributeType::NasIpAddress(Ipv4Addr::new(
                192, 168, 1, 16,
            )));

        packet.attributes.push(RfcAttributeType::NASPort(3));

        let packet_bytes = packet.get_bytes(secret_bytes);

        assert_eq!(expected_bytes, packet_bytes);
    }

    #[test]
    fn create_packet_with_message_authenticator() {
        let secret_bytes = "testing123".as_bytes();
        let expected_bytes = hex::decode(
            "0368002c71624da25c0b5897f70539e019a81eae4f06046700045012ce70fe87a997b44de583cd19bea29321",
        )
        .unwrap();

        let eap_message_bytes = hex::decode("04670004").unwrap().try_into().unwrap();

        let authenticator = hex::decode("b3e22ff855a690280e6c3444c46e663b")
            .unwrap()
            .try_into()
            .unwrap();

        let mut packet = RadiusPacket::new_response(
            super::packet_codes::PacketCode::AccessReject,
            104,
            authenticator,
        );

        packet
            .attributes
            .push(RfcAttributeType::EapMessage(eap_message_bytes));

        packet
            .attributes
            .push(RfcAttributeType::MessageAuthenticator());

        let packet_bytes = packet.get_bytes(secret_bytes);

        assert_eq!(expected_bytes, packet_bytes);
    }

    // https://datatracker.ietf.org/doc/rfc5997/
    #[test]
    fn create_status_server_packet_with_message_authenticator() {
        let secret_bytes = "xyzzy5461".as_bytes();
        let expected_bytes = hex::decode(
            "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3",
        )
        .unwrap();

        let mut packet =
            RadiusPacket::new_request(super::packet_codes::PacketCode::StatusServer, 218);

        // setting this manually here to match expected bytes... it is actually random
        packet.authenticator = hex::decode("8a54f4686fb394c52866e302185d0623")
            .unwrap()
            .try_into()
            .unwrap();

        // hohum, decide on which level we want to add mandatory message authenticators.. responsibility of the packet protocol core or should the server code do this, or force users to  implement handlers to explicitly add it?
        packet
            .attributes
            .push(RfcAttributeType::MessageAuthenticator());

        let packet_bytes = packet.get_bytes(secret_bytes);

        assert_eq!(expected_bytes, packet_bytes);
    }

    #[test]
    fn create_status_server_packet_with_message_authenticator_accounting() {
        let secret_bytes = "xyzzy5461".as_bytes();
        let expected_bytes = hex::decode(
            "0cb30026925f6b66dd5fed571fcb1db7ad3882605012e8d6eabda910875cd91fdade26367858",
        )
        .unwrap();

        let mut packet =
            RadiusPacket::new_request(super::packet_codes::PacketCode::StatusServer, 179);

        // setting this manually here to match expected bytes... it is actually random
        packet.authenticator = hex::decode("925f6b66dd5fed571fcb1db7ad388260")
            .unwrap()
            .try_into()
            .unwrap();

        // hohum, decide on which level we want to add mandatory message authenticators.. responsibility of the packet protocol core or should the server code do this, or force users to  implement handlers to explicitly add it?
        packet
            .attributes
            .push(RfcAttributeType::MessageAuthenticator());

        let packet_bytes = packet.get_bytes(secret_bytes);

        assert_eq!(expected_bytes, packet_bytes);
    }

    #[test]
    fn create_disconnect_request() {
        let secret_bytes = "xyzzy5461".as_bytes();
        let expected_bytes =
            hex::decode("2801001e2ec8a0da729620319be0140bc28e92682c0a3039303432414638").unwrap();

        let mut packet =
            RadiusPacket::new_request(super::packet_codes::PacketCode::DisconnectRequest, 1);

        packet
            .attributes
            .push(RfcAttributeType::AcctSessionId("09042AF8".to_string()));

        let packet_bytes = packet.get_bytes(secret_bytes);

        assert_eq!(expected_bytes, packet_bytes);
    }
}
