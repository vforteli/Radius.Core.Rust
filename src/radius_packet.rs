use byteorder::{BigEndian, ByteOrder};
use rand::Rng;

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
        secret: &str,
    ) -> Result<Self, packet_parsing_error::PacketParsingError> {
        println!("parsing packet!");

        let length_from_packet = BigEndian::read_u16(&packet_bytes[2..4]);

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

        if packet.packetcode == packet_codes::PacketCode::AccountingRequest
            || packet.packetcode == packet_codes::PacketCode::DisconnectRequest
        {
            let hash = calculate_request_authenticator(packet_bytes, &secret.as_bytes());
            println!(
                "Calculated hash {:?}, expected hash {:?}",
                hash, packet.authenticator
            );
            // if (!packet.Authenticator.SequenceEqual(CalculateRequestAuthenticator(packet.SharedSecret, packetBytes)))
            // {
            //     throw new InvalidOperationException($"Invalid request authenticator in packet {packet.Identifier}, check secret?");
            // }
        }

        // The rest are attribute value pairs
        let mut position = 20;
        let mut messageAuthenticatorPosition = 0;

        Ok(packet)
    }
}

pub fn calculate_response_authenticator(
    packet_bytes: &[u8],
    secret_bytes: &[u8],
    authenticator: &[u8; 16],
) -> [u8; 16] {
    return md5::compute(
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

pub fn calculate_request_authenticator(packet_bytes: &[u8], secret_bytes: &[u8]) -> [u8; 16] {
    return calculate_response_authenticator(
        packet_bytes,
        secret_bytes,
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
}

/*
 /// <summary>
        /// Creates a response authenticator
        /// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        /// Actually this means it is the response packet with the request authenticator and secret...
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="requestAuthenticator"></param>
        /// <param name="packetBytes"></param>
        /// <returns>Response authenticator for the packet</returns>
        private byte[] CalculateResponseAuthenticator(byte[] sharedSecret, byte[] requestAuthenticator, byte[] packetBytes)
        {
            var responseAuthenticator = packetBytes.Concat(sharedSecret).ToArray();
            Buffer.BlockCopy(requestAuthenticator, 0, responseAuthenticator, 4, 16);

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(responseAuthenticator);
            }
        }


        /// <summary>
        /// Calculate the request authenticator used in accounting, disconnect and coa requests
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="packetBytes"></param>
        /// <returns></returns>
        internal byte[] CalculateRequestAuthenticator(byte[] sharedSecret, byte[] packetBytes)
        {
            return CalculateResponseAuthenticator(sharedSecret, new byte[16], packetBytes);
        }
*/
/*
while (position < packetLength)
           {
               var typecode = packetBytes[position];
               var length = packetBytes[position + 1];

               var contentBytes = new byte[length - 2];
               Buffer.BlockCopy(packetBytes, position + 2, contentBytes, 0, length - 2);
*/
