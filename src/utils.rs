use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn rand_string() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
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
