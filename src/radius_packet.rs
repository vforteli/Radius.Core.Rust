// use std::{collections::HashMap, fmt::Debug};

use byteorder::{BigEndian, ByteOrder};
use rand::Rng;

use self::rfc_attribute::RfcAttribute;

pub mod packet_codes;
pub mod packet_parsing_error;
pub mod radius_password;
pub mod rfc_attribute;
pub mod rfc_attributes;
pub mod utils;

const PACKET_HEADER_SIZE: usize = 4;
const AUTHENTICATOR_SIZE: usize = 16;

type Authenticator = [u8; 16];

pub struct RadiusPacket {
    pub identifier: u8,
    pub packetcode: packet_codes::PacketCode,
    pub authenticator: Authenticator,
    pub request_authenticator: Authenticator,
    pub attributes: Vec<RfcAttribute>, // hooohum, this should be fixed, because there may be attribute spanning multiple entries
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
        // // Generate random authenticator for access request packets
        // if (Code == PacketCode.AccessRequest || Code == PacketCode.StatusServer)
        // {
        //     using (var csp = RandomNumberGenerator.Create())
        //     {
        //         csp.GetNonZeroBytes(Authenticator);
        //     }
        // }

        // // A Message authenticator is required in status server packets, calculated last
        // if (Code == PacketCode.StatusServer)
        // {
        //     AddAttribute("Message-Authenticator", new byte[16]);
        // }

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

        let mut attribute_bytes: Vec<u8> = Vec::new();
        for attribute in self.attributes {
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

        if self.packetcode == packet_codes::PacketCode::AccountingRequest
            || self.packetcode == packet_codes::PacketCode::DisconnectRequest
            || self.packetcode == packet_codes::PacketCode::CoaRequest
        {
            println!()
        }

        // else if (packet.Code == PacketCode.StatusServer)
        // {
        //     var authenticator = packet.RequestAuthenticator != null ? CalculateResponseAuthenticator(packet.SharedSecret, packet.RequestAuthenticator, packetBytesArray) : packet.Authenticator;
        //     Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);

        //     if (messageAuthenticatorPosition != 0)
        //     {
        //         var temp = new byte[16];
        //         Buffer.BlockCopy(temp, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
        //         var messageAuthenticatorBytes = CalculateMessageAuthenticator(packetBytesArray, packet.SharedSecret, packet.RequestAuthenticator);
        //         Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
        //     }
        // }

        match self.packetcode {
            packet_codes::PacketCode::AccountingRequest
            | packet_codes::PacketCode::DisconnectRequest
            | packet_codes::PacketCode::CoaRequest => {
                println!("hurr");
            }
            packet_codes::PacketCode::StatusServer | packet_codes::PacketCode::StatusClient => {
                println!("durr");
            }
            _ => {
                println!("all other...")
            }
        }
        /*
        // todo refactor this...
           if (packet.Code == PacketCode.AccountingRequest || packet.Code == PacketCode.DisconnectRequest || packet.Code == PacketCode.CoaRequest)
           {
               if (messageAuthenticatorPosition != 0)
               {
                   var temp = new byte[16];
                   Buffer.BlockCopy(temp, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                   var messageAuthenticatorBytes = CalculateMessageAuthenticator(packetBytesArray, packet.SharedSecret, null);
                   Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
               }

               var authenticator = CalculateRequestAuthenticator(packet.SharedSecret, packetBytesArray);
               Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);
           } */

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

        // we can probably allow the buffer to include extra bytes at the end, but these will be ignored
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

                packet.attributes.push(RfcAttribute {
                    code: typecode.to_owned(),
                    value: attribute_content_bytes.to_vec(),
                });
            }

            position += attribute_length;
        }

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

    use byteorder::{BigEndian, ByteOrder};

    use crate::radius_packet::{self, rfc_attribute::RfcAttribute};

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

        // this makes no sense since it should be done in the packet.. but just testing anyway...
        packet.attributes.push(RfcAttribute {
            code: 1,
            value: "nemo".as_bytes().to_vec(),
        });

        packet.attributes.push(RfcAttribute {
            code: 2,
            value: radius_packet::radius_password::encrypt(
                secret_bytes,
                &packet.authenticator,
                "arctangent".as_bytes(),
            ),
        });

        packet.attributes.push(RfcAttribute {
            code: 4,
            value: Ipv4Addr::new(192, 168, 1, 16).octets().to_vec(),
        });

        let mut buffer: [u8; 4] = [0; 4];
        BigEndian::write_u32(&mut buffer, 3);

        packet.attributes.push(RfcAttribute {
            code: 5,
            value: buffer.to_vec(),
        });

        let packet_bytes = packet.get_bytes(secret_bytes);

        assert_eq!(expected_bytes, packet_bytes);
    }
    /*
    *   /// <summary>
       /// Create packet and verify bytes
       /// Example from https://tools.ietf.org/html/rfc2865
       /// </summary>
       [TestCase]
       public void TestCreateAccessRequestPacket()
       {
           var expected = "010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee0406c0a80110050600000003";
           var secret = "xyzzy5461";

           var packet = new RadiusPacket(PacketCode.AccessRequest, 0, secret);
           packet.Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a");
           packet.AddAttribute("User-Name", "nemo");
           packet.AddAttribute("User-Password", "arctangent");
           packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
           packet.AddAttribute("NAS-Port", 3);

           var radiusPacketParser = new RadiusPacketParser(NullLogger<RadiusPacketParser>.Instance, GetDictionary());
           Assert.AreEqual(expected, radiusPacketParser.GetBytes(packet).ToHexString());
       }
    */
}
