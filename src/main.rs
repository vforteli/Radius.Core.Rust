mod radius_packet;

fn main() {
    println!("Hello, world!");

    // let fooo = derp("somestring");
    // println!("herp {0}", fooo);

    // let packet = radius_packet::RadiusPacket {
    //     identifier: 5,
    //     packetcode: radius_packet::packet_codes::PacketCode::AccessAccept,
    //     authenticator: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    //     request_authenticator: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    // };

    // let test_packet_bytes_hex =
    //     "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

    let test_packet_bytes_hex =
        "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234"; // accounting packet with valid authenticator

    let test_packet_bytes = hex::decode(test_packet_bytes_hex).unwrap();

    let secret = "xyzzy5461";

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
            )
        }
        Err(e) => println!("Packet parsing went haywire {}", e),
    }

    // let secret = "somesecret";

    // let packet = radius_packet::RadiusPacket::new(
    //     radius_packet::packet_codes::PacketCode::AccessRequest,
    //     1,
    //     secret,
    // );
}

// fn derp(foo: &str) -> String {
//     return "herp ".to_owned() + foo;
// }
