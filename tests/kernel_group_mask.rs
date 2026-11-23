//! Enable a kernel provider that needs a group mask (set with `TraceSetInformation`) next to one
//! that is enabled by classic `EnableFlags`, and check both deliver events.

use std::time::Duration;

use ferrisetw::provider::kernel_providers;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;

use windows::core::HSTRING;
use windows::Win32::System::LibraryLoader::{LoadLibraryExW, LOAD_LIBRARY_FLAGS};

mod utils;
use utils::{Status, TestKind};

const TEST_LIBRARY_NAME: &str = "wininet.dll";

#[test]
fn kernel_group_mask_and_flags() {
    let handle_events = Status::new(TestKind::ExpectSuccess);
    let handle_notifier = handle_events.notifier();
    let image_load_events = Status::new(TestKind::ExpectSuccess);
    let image_load_notifier = image_load_events.notifier();

    let our_pid = std::process::id();

    let object_manager =
        Provider::kernel_with_group_mask(&kernel_providers::OBJECT_MANAGER_PROVIDER)
            .add_callback(move |record: &EventRecord, _: &SchemaLocator| {
                if record.process_id() == our_pid {
                    handle_notifier.notify_success();
                }
            })
            .build();
    let image_load = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
        .add_callback(move |record: &EventRecord, _: &SchemaLocator| {
            if record.process_id() == our_pid {
                image_load_notifier.notify_success();
            }
        })
        .build();

    let trace = KernelTrace::new()
        .enable(object_manager)
        .enable(image_load)
        .start_and_process()
        .unwrap();

    std::thread::sleep(Duration::from_secs(1));
    for _ in 0..10 {
        drop(std::fs::File::open(std::env::current_exe().unwrap()).unwrap());
    }
    let widename = HSTRING::from(TEST_LIBRARY_NAME);
    // Safety: LoadLibraryExW expects a valid string in lpLibFileName.
    unsafe { LoadLibraryExW(&widename, None, LOAD_LIBRARY_FLAGS::default()) }.unwrap();

    handle_events.assert_passed();
    image_load_events.assert_passed();
    trace.stop().unwrap();
}
