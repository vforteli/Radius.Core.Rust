use md5::{Digest, Md5};

use super::{packet_parsing_error::PacketParsingError, Authenticator};

fn create_key(secret_bytes: &[u8], authenticator_bytes: &Authenticator) -> [u8; 16] {
    return Md5::digest([secret_bytes, authenticator_bytes].concat()).into();
}

fn encrypt_decrypt(input_bytes: &[u8; 16], key_bytes: &[u8; 16]) -> Vec<u8> {
    input_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(&i, &k)| i ^ k)
        .collect()
}

pub fn encrypt(
    secret_bytes: &[u8],
    authenticator_bytes: &Authenticator,
    password_bytes: &[u8],
) -> Vec<u8> {
    let mut key_bytes = create_key(secret_bytes, authenticator_bytes);

    password_bytes
        .chunks(16)
        .flat_map(|chunk| {
            let mut padded_chunk: [u8; 16] = [0; 16];
            padded_chunk[..chunk.len()].copy_from_slice(&chunk);
            let encrypted_chunk_bytes = encrypt_decrypt(&padded_chunk, &key_bytes);
            key_bytes = create_key(
                secret_bytes,
                encrypted_chunk_bytes.as_slice().try_into().unwrap(),
            );

            encrypted_chunk_bytes
        })
        .collect()
}

pub fn decrypt(
    secret_bytes: &[u8],
    authenticator_bytes: &Authenticator,
    password_bytes: &[u8],
) -> Result<String, PacketParsingError> {
    let mut key_bytes = create_key(secret_bytes, authenticator_bytes);

    match String::from_utf8(
        password_bytes
            .chunks(16)
            .flat_map(|chunk| {
                let mut padded_chunk: [u8; 16] = [0; 16];
                padded_chunk[..chunk.len()].copy_from_slice(&chunk);
                let encrypted_chunk_bytes = encrypt_decrypt(&padded_chunk, &key_bytes);
                key_bytes = create_key(secret_bytes, &padded_chunk);

                return encrypted_chunk_bytes;
            })
            .collect(),
    ) {
        Ok(value) => Ok(value.trim_end_matches('\0').to_owned()),
        Err(e) => Err(PacketParsingError::PasswordDecryptionFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_password_1_chunk() {
        let secret_bytes = "xyzzy5461".as_bytes();
        let authenticator_bytes = "1234567890123456".as_bytes();

        let password = "123456789";
        let password_bytes = password.as_bytes();
        let expected_encrypted_bytes = hex::decode("b104742990c283e5938c3a752661d44b").unwrap();

        let actual_encrypted_bytes = encrypt(
            secret_bytes,
            authenticator_bytes.try_into().unwrap(),
            password_bytes,
        );

        assert_eq!(actual_encrypted_bytes, expected_encrypted_bytes);

        let actual_decrypted_password = decrypt(
            secret_bytes,
            authenticator_bytes.try_into().unwrap(),
            actual_encrypted_bytes.as_slice(),
        );

        assert_eq!(actual_decrypted_password.unwrap(), password);
    }

    #[test]
    fn encrypt_decrypt_password_2_chunks() {
        let secret_bytes = "xyzzy5461".as_bytes();
        let authenticator_bytes = "1234567890123456".as_bytes();

        let password = "12345678901234567890";
        let password_bytes = password.as_bytes();
        let expected_encrypted_bytes =
            hex::decode("b104742990c283e593bc0b471555e17dd6956cdf4eec827a4d3d601481c5208a")
                .unwrap();

        let actual_encrypted_bytes = encrypt(
            secret_bytes,
            authenticator_bytes.try_into().unwrap(),
            password_bytes,
        );

        assert_eq!(actual_encrypted_bytes, expected_encrypted_bytes);

        let actual_decrypted_password = decrypt(
            secret_bytes,
            authenticator_bytes.try_into().unwrap(),
            actual_encrypted_bytes.as_slice(),
        );

        assert_eq!(actual_decrypted_password.unwrap(), password);
    }

    #[test]
    fn decrypt_password_invalid_secret() {
        let secret_bytes = "nope".as_bytes();
        let authenticator_bytes = "1234567890123456".as_bytes();

        let encrypted_bytes =
            hex::decode("b104742990c283e593bc0b471555e17dd6956cdf4eec827a4d3d601481c5208a")
                .unwrap();

        let actual_decrypted_password = decrypt(
            secret_bytes,
            authenticator_bytes.try_into().unwrap(),
            encrypted_bytes.as_slice(),
        );

        assert!(actual_decrypted_password.is_err())
    }
}
