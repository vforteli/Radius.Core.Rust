use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

type HmacMd5 = Hmac<Md5>;

/// Creates a response authenticator
/// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
/// Actually this means it is the response packet with the request authenticator and secret...
fn calculate_authenticator(
    packet_header_bytes: &[u8; 4],
    authenticator: &[u8; 16],
    attribute_bytes: &[u8],
    secret_bytes: &[u8],
) -> [u8; 16] {
    return Md5::digest(
        [
            packet_header_bytes as &[u8],
            authenticator,
            attribute_bytes,
            secret_bytes,
        ]
        .concat(),
    )
    .into();
}

/// Calculate the request authenticator used in accounting, disconnect and coa requests
pub fn calculate_request_authenticator(
    packet_header_bytes: &[u8; 4],
    attribute_bytes: &[u8],
    secret_bytes: &[u8],
) -> [u8; 16] {
    return calculate_authenticator(packet_header_bytes, &[0; 16], attribute_bytes, secret_bytes);
}

/// Calculate the response authenticator using authenticator from request
pub fn calculate_response_authenticator(
    packet_header_bytes: &[u8; 4],
    request_authenticator: &[u8; 16],
    attribute_bytes: &[u8],
    secret_bytes: &[u8],
) -> [u8; 16] {
    return calculate_authenticator(
        packet_header_bytes,
        request_authenticator,
        attribute_bytes,
        secret_bytes,
    );
}

/// Calculate the message authenticator found in attribute
pub fn calculate_message_authenticator(
    packet_bytes: &[u8],
    secret_bytes: &[u8],
    message_authenticator_position: usize,
    authenticator: Option<&[u8; 16]>,
) -> [u8; 16] {
    let bytes = [
        &packet_bytes[0..4],
        authenticator.unwrap_or(&packet_bytes[4..20].try_into().unwrap()),
        &packet_bytes[20..message_authenticator_position + 2],
        &[0; 16],
        &packet_bytes[message_authenticator_position + 2 + 16..],
    ]
    .concat();

    println!("Original packet: {:?}", packet_bytes);
    println!("zeroed packet: {:?}", bytes);

    let mut mac = HmacMd5::new_from_slice(secret_bytes).unwrap();
    mac.update(&bytes);

    return mac.finalize().into_bytes().into();
}

/// Calculate the message authenticator to be added to packet
/// Message authentictor attribute MUST be zeroed before
pub fn calculate_message_authenticator_for_access_reject_etc(
    header_bytes: &[u8],
    authenticator_bytes: &[u8],
    attribute_bytes: &[u8],
    secret_bytes: &[u8],
) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(secret_bytes).unwrap();
    mac.update(&[header_bytes, authenticator_bytes, attribute_bytes].concat());
    mac.finalize().into_bytes().into()
}
