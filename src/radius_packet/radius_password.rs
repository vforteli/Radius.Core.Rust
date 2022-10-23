use md5::{Digest, Md5};

pub fn create_key(secret_bytes: &[u8], authenticator_bytes: &[u8; 16]) -> [u8; 16] {
    return Md5::digest([secret_bytes, authenticator_bytes].concat()).into();
}

fn encrypt_decrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {}

pub fn encrypt(
    secret_bytes: &[u8],
    authenticator_bytes: &[u8; 16],
    password_bytes: &[u8],
) -> Vec<u8> {
}

pub fn decrypt(
    secret_bytes: &[u8],
    authenticator_bytes: &[u8; 16],
    password_bytes: &[u8],
) -> Vec<u8> {
}

//  /// <summary>
//         /// Encrypt/decrypt using XOR
//         /// </summary>
//         /// <param name="input"></param>
//         /// <param name="key"></param>
//         /// <returns></returns>
//         private static byte[] EncryptDecrypt(byte[] input, byte[] key)
//         {
//             var output = new byte[input.Length];
//             for (int i = 0; i < input.Length; i++)
//             {
//                 output[i] = (byte)(input[i] ^ key[i]);
//             }
//             return output;
//         }

// /// <summary>
//         /// Decrypt user password
//         /// </summary>
//         /// <param name="sharedSecret"></param>
//         /// <param name="authenticator"></param>
//         /// <param name="passwordBytes"></param>
//         /// <returns></returns>
//         public static string Decrypt(byte[] sharedSecret, byte[] authenticator, byte[] passwordBytes)
//         {
//             var sb = new StringBuilder();
//             var key = CreateKey(sharedSecret, authenticator);

//             for (var n = 1; n <= passwordBytes.Length / 16; n++)
//             {
//                 var temp = new byte[16];
//                 Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);
//                 sb.Append(Encoding.UTF8.GetString(EncryptDecrypt(temp, key)));
//                 key = CreateKey(sharedSecret, temp);
//             }

//             return sb.ToString().Replace("\0", "");
//         }

//         /// <summary>
//         /// Encrypt a password
//         /// </summary>
//         /// <param name="sharedSecret"></param>
//         /// <param name="authenticator"></param>
//         /// <param name="passwordBytes"></param>
//         /// <returns></returns>
//         public static byte[] Encrypt(byte[] sharedSecret, byte[] authenticator, byte[] passwordBytes)
//         {
//             Array.Resize(ref passwordBytes, passwordBytes.Length + (16 - (passwordBytes.Length % 16)));

//             var key = CreateKey(sharedSecret, authenticator);
//             var bytes = new List<byte>();
//             for (var n = 1; n <= passwordBytes.Length / 16; n++)
//             {
//                 var temp = new byte[16];
//                 Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);
//                 var xor = EncryptDecrypt(temp, key);
//                 bytes.AddRange(xor);
//                 key = CreateKey(sharedSecret, xor);
//             }

//             return bytes.ToArray();
//         }

#[cfg(test)]
mod tests {

    #[test]
    fn encrypt_decrypt_password() {
        assert_eq!(true, true)
    }
}
