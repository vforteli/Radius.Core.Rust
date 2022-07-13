use std::net::Ipv4Addr;

// nooo why is this experimental :/
#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum RfcAttributes {
    UserName(String) = 1,
    UserPassword(Vec<u8>) = 2,
    ChapPassword(Vec<u8>) = 3,
    NasIpAddress(Ipv4Addr) = 4,
}
