use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn rand_string() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}

pub fn parse_unk_size_null_utf16_string(v: &[u8]) -> String {
    // TODO: Make sure is aligned
    String::from_utf16_lossy(
        v.chunks_exact(2)
            .into_iter()
            .take_while(|&a| a[0] != 0 && a[1] == 0) // Take until null terminator
            .map(|a| u16::from_ne_bytes([a[0], a[1]]))
            .collect::<Vec<u16>>()
            .as_slice(),
    )
}

pub fn parse_null_utf16_string(v: &[u8]) -> String {
    String::from_utf16_lossy(
        v.chunks_exact(2)
            .into_iter()
            .map(|a| u16::from_ne_bytes([a[0], a[1]]))
            .collect::<Vec<u16>>()
            .as_slice(),
    )
    .trim_matches(char::default())
    .to_string()
}

pub fn parse_utf16_guid(v: &[u8]) -> String {
    String::from_utf16_lossy(
        v.chunks_exact(2)
            .into_iter()
            .map(|a| u16::from_ne_bytes([a[0], a[1]]))
            .collect::<Vec<u16>>()
            .as_slice(),
    )
    .trim_matches(char::default())
    .trim_matches('{')
    .trim_matches('}')
    .to_string()
}
