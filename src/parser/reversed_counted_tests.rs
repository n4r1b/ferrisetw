// Hypothesis under native TDH verification: the count is big-endian;
// the Unicode payload remains UTF-16LE and the tested ANSI payload is ASCII.
use super::{CachedSlices, Parser, ParserError, ParserResult};
use crate::native::tdh_types::{Property, TdhOutType};
use crate::EventRecord;
use std::convert::TryFrom;
use std::sync::Mutex;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_PROPERTY_INFO, EVENT_PROPERTY_INFO_0, EVENT_PROPERTY_INFO_0_0, EVENT_PROPERTY_INFO_1,
    EVENT_PROPERTY_INFO_2, EVENT_RECORD, TDH_INTYPE_REVERSEDCOUNTEDANSISTRING,
    TDH_INTYPE_REVERSEDCOUNTEDSTRING,
};

const UNICODE: u16 = TDH_INTYPE_REVERSEDCOUNTEDSTRING.0 as u16;
const ANSI: u16 = TDH_INTYPE_REVERSEDCOUNTEDANSISTRING.0 as u16;

fn parse_property(in_type: u16, data: &[u8]) -> ParserResult<String> {
    let length = u16::try_from(data.len()).unwrap();
    let native = EVENT_PROPERTY_INFO {
        Anonymous1: EVENT_PROPERTY_INFO_0 {
            nonStructType: EVENT_PROPERTY_INFO_0_0 {
                InType: in_type,
                OutType: TdhOutType::OutTypeString as u16,
                MapNameOffset: 0,
            },
        },
        Anonymous2: EVENT_PROPERTY_INFO_1 { count: 1 },
        Anonymous3: EVENT_PROPERTY_INFO_2 { length },
        ..Default::default()
    };
    let property = Property::new("Str".to_owned(), &native).unwrap();
    let record = EventRecord(EVENT_RECORD {
        UserData: data.as_ptr().cast_mut().cast(),
        UserDataLength: length,
        ..Default::default()
    });
    let parser = Parser {
        properties: std::slice::from_ref(&property),
        record: &record,
        cache: Mutex::new(CachedSlices::default()),
    };
    parser.try_parse("Str")
}

#[test]
fn reversed_counted_unicode_hypothesis() {
    for (data, expected) in [
        (&[0, 0][..], ""),
        (&[0, 4, 0x41, 0, 0x42, 0][..], "AB"),
        (&[0, 4, 0x3e, 0xd8, 0x80, 0xdd][..], "\u{1f980}"),
        (&[0, 2, 0x41, 0, 0x42, 0][..], "A"),
    ] {
        assert_eq!(parse_property(UNICODE, data).unwrap(), expected);
    }
}

#[test]
fn reversed_counted_unicode_rejects_malformed_lengths() {
    for data in [&[0][..], &[0, 4, 0x41, 0][..], &[0, 3, 0x41, 0, 0x42][..]] {
        assert!(matches!(
            parse_property(UNICODE, data),
            Err(ParserError::PropertyError(_))
        ));
    }
}

#[test]
fn reversed_counted_ansi_ascii_hypothesis() {
    for (data, expected) in [(&[0, 0][..], ""), (&[0, 2, b'A', b'B', b'X'][..], "AB")] {
        assert_eq!(parse_property(ANSI, data).unwrap(), expected);
    }
}

#[test]
fn reversed_counted_ansi_rejects_malformed_lengths() {
    for data in [&[0][..], &[0, 3, b'A', b'B'][..]] {
        assert!(matches!(
            parse_property(ANSI, data),
            Err(ParserError::PropertyError(_))
        ));
    }
}
