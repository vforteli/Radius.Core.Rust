use std::net::UdpSocket;

use crate::{packet_handler::PacketHandler, radius_packet::RadiusPacket};

pub struct Server<'a> {
    pub packet_handlers: &'a (dyn PacketHandler + 'a),
}

impl<'a> Server<'a> {
    pub fn new(packet_handler: &'a (dyn PacketHandler + 'a)) -> Self {
        Self {
            packet_handlers: packet_handler,
        }
    }

    pub fn start_listening(self) -> std::io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:1812")?;
        let secret_bytes = "hurrdurr".as_bytes();

        loop {
            let mut buffer = [0; 4096];
            let (length, src) = socket.recv_from(&mut buffer)?;

            let packet = RadiusPacket::parse(&buffer[..length], secret_bytes);

            match packet {
                Ok(packet) => {
                    println!(
                        "
                        identifier: {}
                        code: {:?}
                        authenticator: {:?}        
                        ",
                        packet.identifier, packet.packetcode, packet.authenticator,
                    );

                    for attribute in packet.attributes.iter() {
                        println!("Attribute {:?}", attribute);
                    }

                    match self.packet_handlers.handle_packet(packet, secret_bytes) {
                        Some(response_packet) => {
                            _ = socket.send_to(&response_packet.get_bytes(&secret_bytes), &src);
                        }
                        _ => (),
                    }
                }
                Err(e) => println!("Packet parsing went haywire: {}", e),
            }
        }
    }
}
