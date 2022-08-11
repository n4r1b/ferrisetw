use std::iter;

pub trait LastOsError<T: From<std::io::Error>> {
    fn last_error() -> T {
        T::from(std::io::Error::last_os_error())
    }
}

pub trait EncodeUtf16 {
    fn into_utf16(self) -> Vec<u16>;
}

impl EncodeUtf16 for &str {
    fn into_utf16(self) -> Vec<u16> {
        self.encode_utf16() // Make a UTF-16 iterator
            .chain(iter::once(0)) // Append a null
            .collect() // Collect the iterator into a vector
    }
}

impl EncodeUtf16 for String {
    fn into_utf16(self) -> Vec<u16> {
        self.as_str().into_utf16()
    }
}
