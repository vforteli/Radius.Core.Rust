use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::Rng;

type HmacMd5 = Hmac<Md5>;

pub mod packet_codes;
pub mod packet_parsing_error;

pub struct RadiusPacket {
    pub identifier: u8,
    pub packetcode: packet_codes::PacketCode,
    pub authenticator: [u8; 16],
    pub request_authenticator: [u8; 16],
}

impl RadiusPacket {
    // pub fn new(packetcode: packet_codes::PacketCode, identifier: u8, secret: &str) -> Self {
    //     Self {
    //         packetcode,
    //         identifier,
    //         authenticator: rand::thread_rng().gen::<[u8; 16]>(),
    //         request_authenticator: rand::thread_rng().gen::<[u8; 16]>(),
    //     }
    // }

    pub fn parse(
        packet_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> Result<Self, packet_parsing_error::PacketParsingError> {
        println!("parsing packet!");

        let length_from_packet = BigEndian::read_u16(&packet_bytes[2..4]) as usize;

        // we can probably allow the buffer to include extra bytes at the end, but these will be ignored
        if packet_bytes.len() < length_from_packet.into() {
            return Err(packet_parsing_error::PacketParsingError {
                message: "Package length mismatch...".to_string(),
            });
        }

        let packet = Self {
            identifier: packet_bytes[1],
            packetcode: packet_codes::PacketCode::from(packet_bytes[0]),
            authenticator: packet_bytes[4..20].try_into().unwrap(),
            request_authenticator: rand::thread_rng().gen::<[u8; 16]>(),
        };

        if (packet.packetcode == packet_codes::PacketCode::AccountingRequest
            || packet.packetcode == packet_codes::PacketCode::DisconnectRequest)
            && calculate_request_authenticator(packet_bytes, secret_bytes) != packet.authenticator
        {
            return Err(packet_parsing_error::PacketParsingError {
                message: "Invalid request authenticator in packet, check secret?".to_string(),
            });
        }

        // The rest are attribute value pairs
        let mut position: usize = 20;
        let mut message_authenticator_position: usize = 0;

        while position < length_from_packet {
            let typecode = &packet_bytes[position];
            let attribute_length = packet_bytes[(position + 1)] as usize;
            let attribute_content_length = attribute_length - 2;
            let _content_bytes =
                &packet_bytes[position + 2..position + 2 + attribute_content_length];

            // println!("Content: {:?}", content_bytes);

            // Venvdor specific attribute
            if *typecode == 26 {
                // do some parsing eh
                /*
                    var vsa = new VendorSpecificAttribute(contentBytes);
                    var vendorAttributeDefinition = _radiusDictionary.GetVendorAttribute(vsa.VendorId, vsa.VendorCode);
                    if (vendorAttributeDefinition == null)
                    {
                        _logger.LogInformation($"Unknown vsa: {vsa.VendorId}:{vsa.VendorCode}");
                    }
                    else
                    {
                        try
                        {
                            var content = ParseContentBytes(vsa.Value, vendorAttributeDefinition.Type, typecode, packet.Authenticator, packet.SharedSecret);
                            packet.AddAttributeObject(vendorAttributeDefinition.Name, content);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Something went wrong with vsa {vendorAttributeDefinition.Name}");
                        }
                    }
                */
            } else {
                if *typecode == 80 {
                    // println!("Found message authenticator in packet \\o/");
                    message_authenticator_position = position; // have to save the position to be able to zero it when validating the packet
                }

                // not vsa.. do some parsing eh
                /*
                    var attributeDefinition = _radiusDictionary.GetAttribute(typecode);
                    if (attributeDefinition.Code == 80)
                    {
                        messageAuthenticatorPosition = position;
                    }
                    try
                    {
                        var content = ParseContentBytes(contentBytes, attributeDefinition.Type, typecode, packet.Authenticator, packet.SharedSecret);
                        packet.AddAttributeObject(attributeDefinition.Name, content);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Something went wrong with {attributeDefinition.Name}");
                        _logger.LogDebug($"Attribute bytes: {contentBytes.ToHexString()}");
                    }
                */
            }

            position += attribute_length;
        }

        if message_authenticator_position != 0 {
            println!("Found message authenticator!");
            let calculated_message_authenticator = calculate_message_authenticator(
                packet_bytes,
                secret_bytes,
                message_authenticator_position,
                &[0; 16],
            );

            let expected_message_authenticator = &packet_bytes
                [message_authenticator_position + 2..message_authenticator_position + 2 + 16];

            if expected_message_authenticator != calculated_message_authenticator {
                return Err(packet_parsing_error::PacketParsingError {
                    message: "Invalid message authenticator in packet, check secret?".to_string(),
                });
            }
        }

        Ok(packet)
    }
}

/// Creates a response authenticator
/// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
/// Actually this means it is the response packet with the request authenticator and secret...
pub fn calculate_response_authenticator(
    packet_bytes: &[u8],
    secret_bytes: &[u8],
    authenticator: &[u8; 16],
) -> [u8; 16] {
    return Md5::digest(
        [
            &packet_bytes[0..4],
            authenticator,
            &packet_bytes[20..],
            secret_bytes,
        ]
        .concat(),
    )
    .into();
}

/// Calculate the request authenticator used in accounting, disconnect and coa requests
pub fn calculate_request_authenticator(packet_bytes: &[u8], secret_bytes: &[u8]) -> [u8; 16] {
    return calculate_response_authenticator(packet_bytes, secret_bytes, &[0; 16]);
}

/// Calculate the message authenticator found in attribute
pub fn calculate_message_authenticator(
    packet_bytes: &[u8],
    secret_bytes: &[u8],
    message_authenticator_position: usize,
    _authenticator: &[u8; 16],
) -> [u8; 16] {
    // todo handle authenticator

    // zero the message authenticator value for calculation
    let bytes = [
        &packet_bytes[0..message_authenticator_position + 2],
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
}
