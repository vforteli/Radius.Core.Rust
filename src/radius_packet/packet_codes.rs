#[derive(Debug, PartialEq)]
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum PacketCode {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    StatusServer = 12,
    StatusClient = 13,
    DisconnectRequest = 40,
    DisconnectAck = 41,
    DisconnectNak = 42,
    CoaRequest = 43,
    CoaAck = 44,
    CoaNak = 45,
    Unknown,
}

impl From<u8> for PacketCode {
    fn from(code: u8) -> Self {
        match code {
            1 => return PacketCode::AccessRequest,
            2 => return PacketCode::AccessAccept,
            3 => return PacketCode::AccessReject,
            4 => return PacketCode::AccountingRequest,
            5 => return PacketCode::AccountingResponse,
            11 => return PacketCode::AccessChallenge,
            12 => return PacketCode::StatusServer,
            13 => return PacketCode::StatusClient,
            40 => return PacketCode::DisconnectRequest,
            41 => return PacketCode::DisconnectAck,
            42 => return PacketCode::DisconnectNak,
            43 => return PacketCode::CoaRequest,
            44 => return PacketCode::CoaAck,
            45 => return PacketCode::CoaNak,
            _ => return PacketCode::Unknown,
        };
    }
}
