pub struct RfcAttributeValue {
    pub code: u8,
    pub value: Vec<u8>, // todo hmm, could this be a slice?
}
