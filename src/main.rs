use std::net::UdpSocket;

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

                    for attribute in packet.attributes {
                        println!("Attribute {} : {:?}", attribute.0, attribute.1);
                    }

                    let response_packet = radius_packet::RadiusPacket::new_response(
                        radius_packet::packet_codes::PacketCode::AccessAccept,
                        packet.identifier,
                        packet.authenticator,
                    );

                    let response_packet_bytes = response_packet.get_bytes(&secret);

                    // todo packet handlers
                    socket.send_to(&response_packet_bytes, &src)?;
                }
                Err(e) => println!("Packet parsing went haywire: {}", e.message),
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
                println!("Attribute {} : {:?}", attribute.0, attribute.1);
            }
        }
        Err(e) => println!("Packet parsing went haywire: {}", e.message),
    }

    // let secret = "somesecret";

    // let packet = radius_packet::RadiusPacket::new(
    //     radius_packet::packet_codes::PacketCode::AccessRequest,
    //     1,
    //     secret,
    // );
}
