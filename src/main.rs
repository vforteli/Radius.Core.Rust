use std::net::UdpSocket;

use crate::radius_packet::{
    packet_codes::PacketCode, radius_password::decrypt, rfc_attribute::RfcAttributeValue,
    rfc_attributes::RfcAttributeType, RadiusPacket,
};

mod radius_packet;

fn main() -> std::io::Result<()> {
    {
        let socket = UdpSocket::bind("127.0.0.1:1812")?;
        let secret = "hurrdurr".as_bytes();

        do_stuff();
        loop {
            let mut buffer = [0; 4096];
            let (length, src) = socket.recv_from(&mut buffer)?;

            let packet = radius_packet::RadiusPacket::parse(&buffer[..length], secret);

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

                    let response_packet = match packet.packetcode {
                        PacketCode::AccessRequest => {
                            // yes yes, this should be done in one go...
                            let username = packet.attributes.iter().find_map(|a| match a {
                                RfcAttributeType::UserName(u) => Some(u),
                                _ => None,
                            });

                            let password = packet.attributes.iter().find_map(|a| match a {
                                RfcAttributeType::UserPassword(u) => {
                                    Some(decrypt(secret, &packet.authenticator, u))
                                }
                                _ => None,
                            });

                            println!("Username {:?}, password {:?}", username, password);

                            let response_packet_code = if username.unwrap() == "watho"
                                && password.unwrap().unwrap() == "sup"
                            {
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

                    match response_packet {
                        Some(packet) => {
                            _ = socket.send_to(&packet.get_bytes(&secret), &src);
                        }
                        _ => (),
                    }
                }
                Err(e) => println!("Packet parsing went haywire: {}", e),
            }
        }
    }
}

fn do_stuff() {
    // let test_packet_bytes_hex =
    //     "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

    let test_packet_bytes_hex =
        "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa300ff00ff00ff"; // accounting packet with valid authenticator

    // let test_packet_bytes_hex =
    //     "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3"; // valid messsage authenticator

    let test_packet_bytes = hex::decode(test_packet_bytes_hex).unwrap();

    let secret = "xyzzy5461".as_bytes();

    let packet = radius_packet::RadiusPacket::parse(&test_packet_bytes, secret);

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

            for attribute in packet.attributes {
                let attribute: RfcAttributeValue = attribute.into();
                println!("Attribute {} : {:?}", attribute.code, attribute.value);
            }
        }
        Err(e) => println!("Packet parsing went haywire: {}", e),
    }

    // let secret = "somesecret";

    // let packet = radius_packet::RadiusPacket::new(
    //     radius_packet::packet_codes::PacketCode::AccessRequest,
    //     1,
    //     secret,
    // );
}
