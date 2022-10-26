// todo generate these from dictionary file

use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};

use super::rfc_attribute::RfcAttribute;

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

impl From<u8> for ServiceType {
    fn from(value: u8) -> Self {
        match value {
            1 => ServiceType::Login,
            2 => ServiceType::Framed,
            3 => ServiceType::CallbackLogin,
            4 => ServiceType::CallbackFramed,
            5 => ServiceType::Outbound,
            6 => ServiceType::Administrative,
            7 => ServiceType::NASPrompt,
            8 => ServiceType::AuthenticateOnly,
            9 => ServiceType::CallbackNASPrompt,
            10 => ServiceType::CallCheck,
            11 => ServiceType::CallbackAdministrative,
            _ => panic!("ok this shouldnt be a panic but a result maybe..."),
        }
    }
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

impl From<u8> for AcctStatusType {
    fn from(value: u8) -> Self {
        match value {
            1 => AcctStatusType::Start,
            2 => AcctStatusType::Stop,
            3 => AcctStatusType::InterimUpdate,
            7 => AcctStatusType::AccountingOn,
            8 => AcctStatusType::AccountingOff,
            _ => panic!("ok this shouldnt be a panic but a result maybe..."),
        }
    }
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
    AcctSessionId(String),
    MessageAuthenticator(Vec<u8>),
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
            RfcAttributes::AcctSessionId(_) => 44,
            RfcAttributes::MessageAuthenticator(_) => 80,
        }
    }
}

// todo this stuff needs to be generalized and probably generated
impl Into<RfcAttribute> for RfcAttributes {
    fn into(self) -> RfcAttribute {
        match self {
            RfcAttributes::UserName(v) => RfcAttribute {
                code: 1,
                value: v.as_bytes().to_vec(),
            },
            RfcAttributes::UserPassword(v) => RfcAttribute { code: 2, value: v },
            RfcAttributes::ChapPassword(v) => RfcAttribute { code: 2, value: v },
            RfcAttributes::NasIpAddress(v) => RfcAttribute {
                code: 4,
                value: v.octets().to_vec(),
            },
            RfcAttributes::NASPort(v) => {
                let mut buffer: [u8; 4] = [0; 4];
                BigEndian::write_u32(&mut buffer, v);
                RfcAttribute {
                    code: 5,
                    value: buffer.to_vec(),
                }
            }
            RfcAttributes::ServiceType(v) => RfcAttribute {
                code: 6,
                value: [0, 0, 0, v as u8].to_vec(),
            },
            RfcAttributes::AcctStatusType(v) => RfcAttribute {
                code: 40,
                value: [0, 0, 0, v as u8].to_vec(),
            },
            RfcAttributes::AcctSessionId(v) => RfcAttribute {
                code: 44,
                value: v.as_bytes().to_vec(),
            },
            RfcAttributes::MessageAuthenticator(v) => RfcAttribute { code: 80, value: v },
        }
    }
}

// uh.. this is not safe...
impl From<RfcAttribute> for RfcAttributes {
    fn from(attr: RfcAttribute) -> Self {
        match attr.code {
            1 => RfcAttributes::UserName(String::from_utf8(attr.value).unwrap()),
            2 => RfcAttributes::UserPassword(attr.value),
            3 => RfcAttributes::ChapPassword(attr.value),
            4 => RfcAttributes::NasIpAddress(Ipv4Addr::new(
                attr.value[0],
                attr.value[1],
                attr.value[2],
                attr.value[3],
            )),
            5 => RfcAttributes::NASPort(BigEndian::read_u32(&attr.value)),
            6 => RfcAttributes::ServiceType(attr.value[3].into()),
            40 => RfcAttributes::AcctStatusType(attr.value[3].into()),
            44 => RfcAttributes::AcctSessionId(String::from_utf8(attr.value).unwrap()),
            80 => RfcAttributes::MessageAuthenticator(attr.value),
            _ => panic!("stop being lazy and create a generator for these"),
        }
    }
}
