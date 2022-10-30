// todo generate these from dictionary file

use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};

use super::rfc_attribute_value::RfcAttributeValue;

#[derive(Debug, PartialEq, Clone)]
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
    Voice = 12,
    Fax = 13,
    ModemRelay = 14,
    IAPPRegister = 15,
    IAPPAPCheck = 16,
    AuthorizeOnly = 17,
    FramedManagement = 18,
    AdditionalAuthorization = 19,
    Unknown = 0,
}

impl From<u8> for ServiceType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Login,
            2 => Self::Framed,
            3 => Self::CallbackLogin,
            4 => Self::CallbackFramed,
            5 => Self::Outbound,
            6 => Self::Administrative,
            7 => Self::NASPrompt,
            8 => Self::AuthenticateOnly,
            9 => Self::CallbackNASPrompt,
            10 => Self::CallCheck,
            11 => Self::CallbackAdministrative,
            12 => Self::Voice,
            13 => Self::Fax,
            14 => Self::ModemRelay,
            15 => Self::IAPPRegister,
            16 => Self::IAPPAPCheck,
            17 => Self::AuthorizeOnly,
            18 => Self::FramedManagement,
            19 => Self::AdditionalAuthorization,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum AcctStatusType {
    Start = 1,
    Stop = 2,
    InterimUpdate = 3,
    AccountingOn = 7,
    AccountingOff = 8,
    Unknown = 0,
}

impl From<u8> for AcctStatusType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Start,
            2 => Self::Stop,
            3 => Self::InterimUpdate,
            7 => Self::AccountingOn,
            8 => Self::AccountingOff,
            _ => Self::Unknown, // actually just lazy and couldnt be bothered to add all
        }
    }
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum RfcAttributeType {
    UserName(String),
    UserPassword(Vec<u8>),
    ChapPassword(Vec<u8>),
    NasIpAddress(Ipv4Addr),
    NASPort(u32),
    ServiceType(ServiceType),
    AcctStatusType(AcctStatusType),
    AcctSessionId(String),
    MessageAuthenticator(Vec<u8>),
    Unknown(Vec<u8>),
}

impl Into<u8> for RfcAttributeType {
    fn into(self) -> u8 {
        match self {
            Self::UserName(_) => 1,
            Self::UserPassword(_) => 2,
            Self::ChapPassword(_) => 3,
            Self::NasIpAddress(_) => 4,
            Self::NASPort(_) => 5,
            Self::ServiceType(_) => 6,
            Self::AcctStatusType(_) => 40,
            Self::AcctSessionId(_) => 44,
            Self::MessageAuthenticator(_) => 80,
            Self::Unknown(_) => 0,
        }
    }
}

// todo this stuff needs to be generalized and probably generated
impl Into<RfcAttributeValue> for RfcAttributeType {
    fn into(self) -> RfcAttributeValue {
        match self {
            Self::UserName(v) => RfcAttributeValue {
                code: 1,
                value: v.as_bytes().to_vec(),
            },
            Self::UserPassword(v) => RfcAttributeValue { code: 2, value: v },
            Self::ChapPassword(v) => RfcAttributeValue { code: 2, value: v },
            Self::NasIpAddress(v) => RfcAttributeValue {
                code: 4,
                value: v.octets().to_vec(),
            },
            Self::NASPort(v) => {
                let mut buffer: [u8; 4] = [0; 4];
                BigEndian::write_u32(&mut buffer, v);
                RfcAttributeValue {
                    code: 5,
                    value: buffer.to_vec(),
                }
            }
            Self::ServiceType(v) => RfcAttributeValue {
                code: 6,
                value: [0, 0, 0, v as u8].to_vec(),
            },
            Self::AcctStatusType(v) => RfcAttributeValue {
                code: 40,
                value: [0, 0, 0, v as u8].to_vec(),
            },
            Self::AcctSessionId(v) => RfcAttributeValue {
                code: 44,
                value: v.as_bytes().to_vec(),
            },
            Self::MessageAuthenticator(v) => RfcAttributeValue { code: 80, value: v },
            Self::Unknown(v) => RfcAttributeValue { code: 0, value: v },
        }
    }
}

// uh.. this is not safe...
impl From<RfcAttributeValue> for RfcAttributeType {
    fn from(attr: RfcAttributeValue) -> Self {
        match attr.code {
            1 => Self::UserName(String::from_utf8(attr.value).unwrap()),
            2 => Self::UserPassword(attr.value),
            3 => Self::ChapPassword(attr.value),
            4 => Self::NasIpAddress(Ipv4Addr::new(
                attr.value[0],
                attr.value[1],
                attr.value[2],
                attr.value[3],
            )),
            5 => Self::NASPort(BigEndian::read_u32(&attr.value)),
            6 => Self::ServiceType(attr.value[3].into()),
            40 => Self::AcctStatusType(attr.value[3].into()),
            44 => Self::AcctSessionId(String::from_utf8(attr.value).unwrap()),
            80 => Self::MessageAuthenticator(attr.value),
            _ => Self::Unknown(attr.value), // unknown aka too lazy to create the dictionary parser and include all rfc attributes
        }
    }
}
