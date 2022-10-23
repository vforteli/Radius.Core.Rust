// use std::{collections::HashMap, fmt::Debug};

use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::Rng;

type HmacMd5 = Hmac<Md5>;

pub mod packet_codes;
pub mod packet_parsing_error;
pub mod rfc_attributes;

pub struct RadiusPacket {
    pub identifier: u8,
    pub packetcode: packet_codes::PacketCode,
    pub authenticator: [u8; 16],
    pub request_authenticator: [u8; 16],
    pub attributes: Vec<(u8, Vec<u8>)>, // hooohum, this should be fixed, because there may be attribute spanning multiple entries
}

impl RadiusPacket {
    pub fn new_response(
        packetcode: packet_codes::PacketCode,
        identifier: u8,
        request_authenticator: [u8; 16],
    ) -> Self {
        Self {
            packetcode,
            identifier,
            authenticator: [0; 16],
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
            authenticator: rand::thread_rng().gen::<[u8; 16]>(),
            request_authenticator: [0; 16],
            attributes: Vec::new(),
        }
    }

    pub fn get_bytes(self, secret_bytes: &[u8]) -> Vec<u8> {
        let mut header_bytes: [u8; 4] = [self.packetcode as u8, self.identifier, 0, 0];

        let mut attribute_bytes: Vec<u8> = Vec::new();
        for attribute in self.attributes {
            println!("adding attribute {} : {:?}", attribute.0, attribute.1);
            attribute_bytes.extend([attribute.0]);
            attribute_bytes.extend([(attribute.1.len() as u8) + 2]);
            attribute_bytes.extend(attribute.1);
        }

        let packet_length_bytes = 4 + 16 + attribute_bytes.len(); // header + authenticator + attributes

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

        let authenticator_bytes = calculate_response_authenticator(
            &header_bytes,
            &self.request_authenticator,
            &attribute_bytes,
            secret_bytes,
        );

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
            && calculate_request_authenticator(
                &packet_bytes[0..4].try_into().unwrap(),
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

                // do some parsing...
                packet
                    .attributes
                    .extend([(typecode.to_owned(), attribute_content_bytes.to_vec())]);
            }

            position += attribute_length;
        }

        if message_authenticator_position != 0 {
            println!("Found message authenticator!");
            let calculated_message_authenticator = calculate_message_authenticator(
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

/// Creates a response authenticator
/// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
/// Actually this means it is the response packet with the request authenticator and secret...
pub fn calculate_authenticator(
    packet_header_bytes: &[u8; 4],
    authenticator: &[u8; 16],
    attribute_bytes: &[u8],
    secret_bytes: &[u8],
) -> [u8; 16] {
    return Md5::digest(
        [
            packet_header_bytes as &[u8],
            authenticator,
            attribute_bytes,
            secret_bytes,
        ]
        .concat(),
    )
    .into();
}

/// Calculate the request authenticator used in accounting, disconnect and coa requests
pub fn calculate_request_authenticator(
    packet_header_bytes: &[u8; 4],
    attribute_bytes: &[u8],
    secret_bytes: &[u8],
) -> [u8; 16] {
    return calculate_authenticator(packet_header_bytes, &[0; 16], attribute_bytes, secret_bytes);
}

/// Calculate the response authenticator using authenticator from request
pub fn calculate_response_authenticator(
    packet_header_bytes: &[u8; 4],
    request_authenticator: &[u8; 16],
    attribute_bytes: &[u8],
    secret_bytes: &[u8],
) -> [u8; 16] {
    return calculate_authenticator(
        packet_header_bytes,
        request_authenticator,
        attribute_bytes,
        secret_bytes,
    );
}

/// Calculate the message authenticator found in attribute
pub fn calculate_message_authenticator(
    packet_bytes: &[u8],
    secret_bytes: &[u8],
    message_authenticator_position: usize,
    authenticator: Option<&[u8; 16]>,
) -> [u8; 16] {
    let bytes = [
        &packet_bytes[0..4],
        authenticator.unwrap_or(&packet_bytes[4..20].try_into().unwrap()),
        &packet_bytes[20..message_authenticator_position + 2],
        &[0; 16],
        &packet_bytes[message_authenticator_position + 2 + 16..],
    ]
    .concat();

    println!("Original packet: {:?}", packet_bytes);
    println!("zeroed packet: {:?}", bytes);

    let mut mac = HmacMd5::new_from_slice(secret_bytes).unwrap();
    mac.update(&bytes);

    return mac.finalize().into_bytes().into();
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use byteorder::{BigEndian, ByteOrder};

    use super::RadiusPacket;

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
        packet.authenticator = hex::decode("00000000000000000000000000000000")
        // packet.authenticator = hex::decode("0f403f9473978057bd83d5cb98f4227a")
            .unwrap()
            .try_into()
            .unwrap();

        // this makes no sense since it should be done in the packet.. but just testing anyway...
        packet.attributes.push((1, "nemo".as_bytes().to_vec()));

        packet
            .attributes
            .push((2, "arctangent".as_bytes().to_vec()));
            
        packet
            .attributes
            .push((4, Ipv4Addr::new(192, 168, 1, 16).octets().to_vec())); // todo fix.. this should be bytes...

        let mut buffer: [u8; 4] = [0; 4];
        BigEndian::write_u32(&mut buffer, 3);

        packet.attributes.push((5, buffer.to_vec()));

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
