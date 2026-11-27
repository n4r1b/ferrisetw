use super::{CachedSlices, Parser, ParserError, ParserResult};
use crate::native::tdh_types::{Property, TdhOutType};
use crate::EventRecord;
use std::convert::TryFrom;
use std::mem::{size_of, size_of_val};
use std::sync::Mutex;
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    DecodingSourceWbem, TdhFormatProperty, EVENT_PROPERTY_INFO, EVENT_PROPERTY_INFO_0,
    EVENT_PROPERTY_INFO_0_0, EVENT_PROPERTY_INFO_1, EVENT_PROPERTY_INFO_2, EVENT_RECORD,
    TDH_INTYPE_REVERSEDCOUNTEDANSISTRING, TRACE_EVENT_INFO,
};

const REVERSED_ANSI: u16 = TDH_INTYPE_REVERSEDCOUNTEDANSISTRING.0 as u16;

#[link(name = "kernel32")]
extern "system" {
    fn GetACP() -> u32;
}

fn fixture(payload: &[u8]) -> Vec<u8> {
    let mut bytes = u16::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

fn property(out_type: u16, length: u16) -> EVENT_PROPERTY_INFO {
    EVENT_PROPERTY_INFO {
        Anonymous1: EVENT_PROPERTY_INFO_0 {
            nonStructType: EVENT_PROPERTY_INFO_0_0 {
                InType: REVERSED_ANSI,
                OutType: out_type,
                MapNameOffset: 0,
            },
        },
        Anonymous2: EVENT_PROPERTY_INFO_1 { count: 1 },
        Anonymous3: EVENT_PROPERTY_INFO_2 { length },
        ..Default::default()
    }
}

fn parse(out_type: u16, bytes: &[u8]) -> ParserResult<String> {
    let length = u16::try_from(bytes.len()).unwrap();
    let property = Property::new("Str".to_owned(), &property(out_type, length)).unwrap();
    let record = EventRecord(EVENT_RECORD {
        UserData: bytes.as_ptr().cast_mut().cast(),
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

fn native_ansi_oracle(payload: &[u8]) -> Option<String> {
    assert!(payload.len() <= 2 && !payload.contains(&0));
    if std::str::from_utf8(payload).is_ok() {
        return None;
    }
    let bytes = fixture(payload);
    let out_type = TdhOutType::OutTypeString;
    let info = TRACE_EVENT_INFO {
        DecodingSource: DecodingSourceWbem,
        PropertyCount: 1,
        TopLevelPropertyCount: 1,
        EventPropertyInfoArray: [property(out_type as u16, 0)],
        ..Default::default()
    };
    let mut output = [0u16; 16];
    let mut size_bytes = size_of_val(&output) as u32;
    let mut consumed = 0;
    // The metadata, count-bounded input, and initialized output all remain
    // allocated for the call. The declared count matches the input slice.
    let status = unsafe {
        TdhFormatProperty(
            &info,
            None,
            size_of::<usize>() as u32,
            REVERSED_ANSI,
            out_type as u16,
            0,
            &bytes,
            &mut size_bytes,
            Some(PWSTR(output.as_mut_ptr())),
            &mut consumed,
        )
    };
    if status != 0 || usize::from(consumed) != bytes.len() {
        return None;
    }
    let units = output.get(..usize::try_from(size_bytes).ok()? / size_of::<u16>())?;
    let end = units.iter().position(|&unit| unit == 0)?;
    let text = String::from_utf16(&units[..end]).ok()?;
    if text.is_empty() || text.contains('\u{fffd}') {
        return None;
    }
    Some(text)
}

#[test]
fn reversed_ansi_utf8_out_type_decodes_valid_utf8_without_terminator() {
    let bytes = fixture(&[0xc3, 0xa9]);
    assert_eq!(
        parse(TdhOutType::OutTypeUtf8 as u16, &bytes).unwrap(),
        "\u{e9}"
    );
}

#[test]
fn reversed_ansi_utf8_out_types_reject_invalid_utf8() {
    let bytes = fixture(&[0xc0]);
    for out_type in [
        35, // TDH_OUTTYPE_UTF8
        34, // TDH_OUTTYPE_JSON
        28, // TDH_OUTTYPE_XML
    ] {
        assert!(matches!(
            parse(out_type, &bytes),
            Err(ParserError::Utf8Error(_))
        ));
    }
}

#[test]
fn reversed_ansi_xml_and_json_out_types_decode_utf8() {
    let bytes = fixture(&[0xc3, 0xa9]);
    for out_type in [34, 28] {
        // TDH_OUTTYPE_JSON and TDH_OUTTYPE_XML
        assert_eq!(parse(out_type, &bytes).unwrap(), "\u{e9}");
    }
}

#[test]
fn reversed_ansi_preserves_counted_nuls() {
    let bytes = fixture(b"A\0B\0");
    for out_type in [TdhOutType::OutTypeString, TdhOutType::OutTypeUtf8] {
        assert_eq!(parse(out_type as u16, &bytes).unwrap(), "A\0B\0");
    }
}

#[test]
fn reversed_ansi_string_out_type_decodes_ascii_without_terminator() {
    let bytes = fixture(b"AB");
    assert_eq!(
        parse(TdhOutType::OutTypeString as u16, &bytes).unwrap(),
        "AB"
    );
}

#[test]
fn reversed_ansi_string_out_type_matches_windows_acp_for_non_utf8() {
    // GetACP accepts no arguments and does not use caller-owned memory.
    let acp = unsafe { GetACP() };
    if acp == 65001 {
        eprintln!("ACP 65001 has no valid non-UTF-8 sample");
        return;
    }

    // Choose a native-valid sample without assuming a single-byte code page.
    let candidates: [&[u8]; 7] = [
        &[0xc0],
        &[0xe9],
        &[0x80],
        &[0x81, 0x40],
        &[0x82, 0xa0],
        &[0xa1, 0xa1],
        &[0xa4, 0x40],
    ];
    for sample in candidates {
        if let Some(expected) = native_ansi_oracle(sample) {
            eprintln!("ACP {acp}, sample {sample:02x?}, TDH output {expected:?}");
            assert_eq!(
                parse(TdhOutType::OutTypeString as u16, &fixture(sample)).unwrap(),
                expected
            );
            return;
        }
    }
    eprintln!("No valid non-UTF-8 sample in this fixture for ACP {acp}");
}
