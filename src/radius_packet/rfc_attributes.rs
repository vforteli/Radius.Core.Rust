// todo generate these from dictionary file

use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum ServiceType {
    Login = 1,
    Framed = 2,
    CallbackLogin = 3,
    CallbackFramed = 4,
    Outbound = 5,
    Administrative = 6,
    NASPrompt = 7,
    AuthenticateOnly = 8,
    CallbackNASPrompt = 9,
    CallCheck = 10,
    CallbackAdministrative = 11,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum AcctStatusType {
    Start = 1,
    Stop = 2,
    InterimUpdate = 3,
    AccountingOn = 7,
    AccountingOff = 8,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum RfcAttributes {
    UserName(String),
    UserPassword(Vec<u8>),
    ChapPassword(Vec<u8>),
    NasIpAddress(Ipv4Addr),
    NASPort(u32),
    ServiceType(ServiceType),
    AcctStatusType(AcctStatusType),
}

impl Into<u8> for RfcAttributes {
    fn into(self) -> u8 {
        match self {
            RfcAttributes::UserName(_) => 1,
            RfcAttributes::UserPassword(_) => 2,
            RfcAttributes::ChapPassword(_) => 3,
            RfcAttributes::NasIpAddress(_) => 4,
            RfcAttributes::NASPort(_) => 5,
            RfcAttributes::ServiceType(_) => 6,
            RfcAttributes::AcctStatusType(_) => 40,
        }
    }
}

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
