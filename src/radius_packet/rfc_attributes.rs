// use std::net::Ipv4Addr;

// // nooo why is this experimental :/
// #[derive(Debug, PartialEq)]
// #[repr(u8)]
// pub enum RfcAttributes {
//     UserName(String) = 1,
//     UserPassword(Vec<u8>) = 2,
//     ChapPassword(Vec<u8>) = 3,
//     NasIpAddress(Ipv4Addr) = 4,
//     NASPort(u32) = 5,
//     ServiceType(ServiceType) = 6,
//     AcctStatusType = 40,
// }

// #[derive(Debug, PartialEq)]
// #[repr(u8)]
// pub enum ServiceType {
//     Login = 1,
//     Framed = 2,
//     CallbackLogin = 3,
//     CallbackFramed = 4,
//     Outbound = 5,
//     Administrative = 6,
//     NASPrompt = 7,
//     AuthenticateOnly = 8,
//     CallbackNASPrompt = 9,
//     CallCheck = 10,
//     CallbackAdministrative = 11,
// }
