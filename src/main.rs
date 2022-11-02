use std::net::IpAddr;
use std::net::Ipv4Addr;

use server::{Client, Server};
use test_packet_handler::TestPacketHandler;
mod packet_handler;
mod radius_packet;
mod server;
mod test_packet_handler;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    {
        let test_handler = TestPacketHandler {};
        let secret_bytes = "hurrdurr".as_bytes();

        let mut server = Server::new();

        server.packet_handlers_clients.insert(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Client {
                secret_bytes,
                packet_handler: &test_handler,
            },
        );
        server.packet_handlers_clients.insert(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Client {
                secret_bytes,
                packet_handler: &test_handler,
            },
        );

        server.start_listening(1812).await
    }
}
