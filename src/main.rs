use server::Server;
use test_packet_handler::TestPacketHandler;

use crate::radius_packet::rfc_attribute_value::RfcAttributeValue;

mod packet_handler;
mod radius_packet;
mod server;
mod test_packet_handler;

fn main() -> std::io::Result<()> {
    {
        do_stuff();

        let server = Server::new(&TestPacketHandler {});
        server.start_listening()
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
