#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum AcctStatusType {
    Start = 1,
    Stop = 2,
    InterimUpdate = 3,
    AccountingOn = 7,
    AccountingOff = 8,
}
