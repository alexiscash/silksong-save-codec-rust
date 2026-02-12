use base64::{engine::general_purpose, Engine as _};
use aes::Aes256;
use ecb::Decryptor;
use block_padding::Pkcs7;
use ecb::cipher::{BlockDecryptMut, KeyInit};

const AES_KEY_STRING: &str = "UKu52ePUBwetZ9wNX88o54dnfKRu0T1l";
const CSHARP_HEADER: [u8; 22] = [0, 1, 0, 0, 0, 255, 255, 255,
                       255, 1, 0, 0, 0, 0, 0, 0, 0, 6, 1, 0, 0, 0];

fn decrypt(payload: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    let without_header = &payload[CSHARP_HEADER.len()..payload.len() - 1];

    let mut len_count = 0;
    for i in 0..5 {
        len_count += 1;
        if (without_header[i] & 0x80) == 0 {
            break;
        }
    }

    let no_header = &without_header[len_count..];

    let mut b64_encrypted = general_purpose::STANDARD.decode(no_header)?;

    let key = AES_KEY_STRING.as_bytes();

    let cipher = Decryptor::<Aes256>::new_from_slice(key)
        .map_err(|e| format!("Invalid key length: {:?}",e))?;

    let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut b64_encrypted)
        .map_err(|e| format!("Unpad error: {:?}", e))?;

    let text = std::str::from_utf8(decrypted)?.to_string();

    Ok(text)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("something is happening");

    let raw = std::fs::read("saves/user2.dat")?;

    println!("{}", &decrypt(raw)?);
    

    Ok(())
}