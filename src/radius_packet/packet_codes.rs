/**
 * Radius packet codes
 * Actually these could be split into request and response codes to better type the new_request function in radius packet
 */
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
            1 => PacketCode::AccessRequest,
            2 => PacketCode::AccessAccept,
            3 => PacketCode::AccessReject,
            4 => PacketCode::AccountingRequest,
            5 => PacketCode::AccountingResponse,
            11 => PacketCode::AccessChallenge,
            12 => PacketCode::StatusServer,
            13 => PacketCode::StatusClient,
            40 => PacketCode::DisconnectRequest,
            41 => PacketCode::DisconnectAck,
            42 => PacketCode::DisconnectNak,
            43 => PacketCode::CoaRequest,
            44 => PacketCode::CoaAck,
            45 => PacketCode::CoaNak,
            _ => PacketCode::Unknown,
        }
    }
}
