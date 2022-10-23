use std::fmt;

#[derive(Debug, Clone)]
pub enum PacketParsingError {
    InvalidMessageAuthenticator,
    InvalidLength,
    InvalidRequestAuthenticator,
}

impl fmt::Display for PacketParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PacketParsingError::InvalidLength => write!(f, "Packed length mismatch"),
            PacketParsingError::InvalidMessageAuthenticator => write!(
                f,
                "Invalid message authenticator attribute found in packet, check secret?"
            ),
            PacketParsingError::InvalidRequestAuthenticator => write!(
                f,
                "Invalid request authenticator found in packet, check secret?"
            ),
        }
    }
}
