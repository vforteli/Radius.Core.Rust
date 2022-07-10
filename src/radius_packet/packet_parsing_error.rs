use std::fmt;

pub struct PacketParsingError {
    pub message: String,
}

impl fmt::Display for PacketParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Failed parsing packet")
    }
}

impl fmt::Debug for PacketParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ file: {}, line: {} }}", file!(), line!())
    }
}
