use std::{collections::HashMap, net::IpAddr};

use tokio::net::UdpSocket;

use crate::{packet_handler::PacketHandler, radius_packet::RadiusPacket};

pub struct Client<'a> {
    pub secret_bytes: &'a [u8],
    pub packet_handler: &'a (dyn PacketHandler + 'a),
}

pub struct Server<'a> {
    pub packet_handlers_clients: HashMap<IpAddr, Client<'a>>,
}

impl<'a> Server<'a> {
    pub fn new() -> Self {
        Self {
            packet_handlers_clients: HashMap::new(),
        }
    }

    pub async fn start_listening(self, port: u16) -> std::io::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:".to_string() + &port.to_string()).await?;

        println!("Listening on port: {}", port);

        loop {
            // todo, async and/or thread pool?
            let mut buffer = [0; 4096];
            let (length, src) = socket.recv_from(&mut buffer).await?;

            let handler = self.packet_handlers_clients.get(&src.ip());

            match handler {
                Some(handler) => {
                    match RadiusPacket::parse(&buffer[..length], &handler.secret_bytes) {
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

                            match handler
                                .packet_handler
                                .handle_packet(packet, &handler.secret_bytes)
                            {
                                Some(response_packet) => {
                                    _ = socket
                                        .send_to(
                                            &response_packet.get_bytes(&handler.secret_bytes),
                                            &src,
                                        )
                                        .await?;
                                }
                                _ => (),
                            }
                        }
                        Err(e) => println!("Packet parsing went haywire: {}", e),
                    }
                }
                None => {
                    println!("No handler found for ip {}, ignoring", src.ip())
                }
            }
        }
    }
}
