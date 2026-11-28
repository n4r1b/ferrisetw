#[cfg(test)]
mod afd_130_probe {
    use crate::native::tdh_types::PropertyLength;
    use crate::parser::{tdh, Parser, PropertyInfo};
    use crate::provider::Provider;
    use crate::trace::UserTrace;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows::Win32::System::Diagnostics::Etw::{TdhGetProperty, PROPERTY_DATA_DESCRIPTOR};

    #[test]
    #[ignore = "requires permission to create an ETW session with the AFD provider"]
    fn afd_indirect_address_matches_tdh() {
        let (tx, rx) = mpsc::channel();
        let pid = std::process::id();
        let provider = Provider::by_guid(0xe53c6823_7bb8_44bb_90dc_3f86090d48a6)
            .any(u64::MAX)
            .level(5)
            .add_callback(
                move |record: &crate::EventRecord,
                      locator: &crate::schema_locator::SchemaLocator| {
                    if record.process_id() != pid {
                        return;
                    }
                    let Ok(schema) = locator.event_schema(record) else {
                        return;
                    };
                    let Ok(properties) = schema.try_properties() else {
                        return;
                    };
                    let Some(prop) = properties.iter().find(|p| {
                        p.name == "Address"
                            && matches!(
                                p.info,
                                PropertyInfo::Value {
                                    length: PropertyLength::Index(_),
                                    ..
                                }
                            )
                    }) else {
                        return;
                    };
                    let parser = Parser::create(record, &schema);
                    let parsed = match parser.try_parse::<Vec<u8>>(&prop.name) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let _ = tx.send(Err(format!(
                                "event {} parser: {:?}",
                                record.event_id(),
                                e
                            )));
                            return;
                        }
                    };
                    let size = match tdh::property_size(record, &prop.name) {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = tx.send(Err(format!("TDH size: {:?}", e)));
                            return;
                        }
                    };
                    let name: Vec<u16> = prop.name.encode_utf16().chain(Some(0)).collect();
                    let desc = PROPERTY_DATA_DESCRIPTOR {
                        PropertyName: name.as_ptr() as u64,
                        ArrayIndex: u32::MAX,
                        ..Default::default()
                    };
                    let mut expected = vec![0; size as usize];
                    let status = unsafe {
                        TdhGetProperty(record.as_raw_ptr(), None, &[desc], &mut expected)
                    };
                    let _ = tx.send(
                        if status == 0 && !expected.is_empty() && parsed == expected {
                            Ok(format!(
                                "event={} address_len={} bytes match TDH",
                                record.event_id(),
                                size
                            ))
                        } else {
                            Err(format!(
                                "event={} status={} parsed_len={} tdh_len={} equal={}",
                                record.event_id(),
                                status,
                                parsed.len(),
                                size,
                                parsed == expected
                            ))
                        },
                    );
                },
            )
            .build();
        let trace = UserTrace::new()
            .named(format!("ferrisetw-130-afd-{}", pid))
            .stop_if_exist(false)
            .enable(provider)
            .start_and_process()
            .expect("start test ETW session");
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..30 {
            sender
                .send_to(b"ferrisetw130", receiver.local_addr().unwrap())
                .unwrap();
        }
        let result = rx.recv_timeout(Duration::from_secs(10));
        trace.stop().expect("stop test ETW session");
        println!("AFD_PROBE={:?}", result);
        assert!(
            matches!(result, Ok(Ok(_))),
            "expected AFD Address with PROPERTY_PARAM_LENGTH and matching TDH bytes"
        );
    }
}
