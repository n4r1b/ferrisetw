//! Native API - Performance Logs and Alerts COM
//!
//! The `pla` module is an abstraction layer for the Windows evntrace library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `evntrace` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the the crate level provide a safe API to interact
//! with the crate
use std::mem::MaybeUninit;
use windows::core::GUID;
use windows::Win32::Foundation::BSTR;

/// Pla native module errors
#[derive(Debug, PartialEq)]
pub enum PlaError {
    /// Represents a Provider not found Error
    NotFound,
    /// Represents an HRESULT common error
    ComHResultError(HResult),
}

/// Wrapper over common HRESULT native errors (Incomplete)
#[derive(Debug, PartialEq)]
pub enum HResult {
    /// Represents S_OK
    HrOk,
    /// Represents E_ABORT
    HrAbort,
    /// Represents E_ACCESSDENIED
    HrAccessDenied,
    /// Represents E_FAIL
    HrFail,
    /// Represents E_INVALIDARG
    HrInvalidArg,
    /// Represents E_OUTOFMEMORY
    HrOutOfMemory,
    /// Represent an HRESULT not implemented in the Wrapper
    NotImplemented(i32),
}

impl From<i32> for HResult {
    fn from(hr: i32) -> HResult {
        match hr {
            0x0 => HResult::HrOk,
            -2147467260 => HResult::HrAbort,
            -2147024891 => HResult::HrAccessDenied,
            -2147467259 => HResult::HrFail,
            -2147024809 => HResult::HrInvalidArg,
            -2147024882 => HResult::HrOutOfMemory,
            _ => HResult::NotImplemented(hr),
        }
    }
}

impl From<i32> for PlaError {
    fn from(val: i32) -> PlaError {
        PlaError::ComHResultError(HResult::from(val))
    }
}

pub(crate) type ProvidersComResult<T> = Result<T, PlaError>;

const VT_UI4: u16 = 0x13;
// We are just going to use VT_UI4 so we won't bother replicating the full VARIANT struct
// Not using Win32::Automation::VARIANT for commodity
#[repr(C)]
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Variant {
    vt: u16,
    w_reserved1: u16,
    w_reserved2: u16,
    w_reserved3: u16,
    val: u32,
}

impl Variant {
    pub fn new(vt: u16, val: u32) -> Self {
        Variant{
            vt,
            val,
            ..Default::default()
        }
    }

    pub fn increment_val(&mut self) {
        self.val += 1;
    }
    pub fn get_val(&self) -> u32 {
        self.val
    }
}

fn check_hr(hr: i32) -> ProvidersComResult<()> {
    let res = HResult::from(hr);
    if res != HResult::HrOk {
        return Err(PlaError::ComHResultError(res));
    }

    Ok(())
}

// https://github.com/microsoft/krabsetw/blob/31679cf84bc85360158672699f2f68a821e8a6d0/krabs/krabs/provider.hpp#L487
pub(crate) unsafe fn get_provider_guid(name: &str) -> ProvidersComResult<GUID> {
    com::runtime::init_runtime()?;

    let all_providers = com::runtime::create_instance::<
        pla_interfaces::ITraceDataProviderCollection,
    >(&pla_interfaces::CLSID_TRACE_DATA_PROV_COLLECTION)?;

    let mut guid: MaybeUninit<GUID> = MaybeUninit::uninit();
    let mut hr = all_providers.get_trace_data_providers(BSTR::from(""));
    check_hr(hr)?;

    // could we assume count is unsigned... let's trust that count won't be negative
    let mut count = 0;
    hr = all_providers.get_count(&mut count);
    check_hr(hr)?;

    let mut index = Variant::new(VT_UI4, 0);
    while index.get_val() < count as u32 {
        let mut provider = None;

        hr = all_providers.get_item(index, &mut provider);
        check_hr(hr)?;

        // We can safely unwrap after check_hr
        let mut raw_name: MaybeUninit<BSTR> = MaybeUninit::uninit();
        let provider = provider.unwrap();
        provider.get_display_name(raw_name.as_mut_ptr());
        check_hr(hr)?;

        let raw_name = raw_name.assume_init();
        let prov_name = String::from_utf16_lossy(raw_name.as_wide());

        index.increment_val();
        // check if matches, if it does get guid and break
        if prov_name.eq(name) {
            hr = provider.get_guid(guid.as_mut_ptr());
            check_hr(hr)?;
            println!("{}", prov_name);
            break;
        }
    }

    if index.get_val() == count as u32 {
        return Err(PlaError::NotFound);
    }

    // we can assume the guid is init if we reached this point eoc would return Error
    Ok(guid.assume_init())
}

mod pla_interfaces {
    use super::{GUID, Variant, BSTR};
    use com::sys::IID;
    use com::{interfaces, interfaces::iunknown::IUnknown, sys::HRESULT};

    interfaces! {
        // functions parameters not defined unless necessary
        #[uuid("00020400-0000-0000-C000-000000000046")]
        pub unsafe interface IDispatch: IUnknown {
            pub fn get_type_info_count(&self) -> HRESULT;
            pub fn get_type_info(&self) -> HRESULT;
            pub fn get_ids_of_names(&self) -> HRESULT;
            pub fn invoke(&self) -> HRESULT;
        }

        // pla.h
        #[uuid("03837510-098b-11d8-9414-505054503030")]
        pub unsafe interface ITraceDataProviderCollection: IDispatch {
            pub fn get_count(&self, retval: *mut i32) -> HRESULT;
            pub fn get_item(
                 &self,
                 #[pass_through]
                 index: Variant,
                 provider: *mut Option<ITraceDataProvider>,
             ) -> HRESULT;
            pub fn get__new_enum(&self) -> HRESULT;
            pub fn add(&self) -> HRESULT;
            pub fn remove(&self) -> HRESULT;
            pub fn clear(&self) -> HRESULT;
            pub fn add_range(&self) -> HRESULT;
            pub fn create_trace_data_provider(&self) -> HRESULT;
            pub fn get_trace_data_providers(
                &self,
                #[pass_through]
                server: BSTR
            ) -> HRESULT;
            pub fn get_trace_data_providers_by_process(&self) -> HRESULT;
        }

        #[uuid("03837512-098b-11d8-9414-505054503030")]
        pub unsafe interface ITraceDataProvider: IDispatch {
           pub fn get_display_name(
                &self,
                #[pass_through]
                name: *mut BSTR
           ) -> HRESULT;
           pub fn put_display_name(&self) -> HRESULT;
           pub fn get_guid(
                &self,
                #[pass_through]
                guid: *mut GUID
           ) -> HRESULT;
           pub fn put_guid(&self) -> HRESULT;
           pub fn get_level(&self) -> HRESULT;
           pub fn get_keywords_any(&self) -> HRESULT;
           pub fn get_keywords_all(&self) -> HRESULT;
           pub fn get_properties(&self) -> HRESULT;
           pub fn get_filter_enabled(&self) -> HRESULT;
           pub fn put_filter_enabled(&self) -> HRESULT;
           pub fn get_filter_type(&self) -> HRESULT;
           pub fn put_filter_type(&self) -> HRESULT;
           pub fn get_filter_data(&self) -> HRESULT;
           pub fn put_filter_data(&self) -> HRESULT;
           pub fn query(&self) -> HRESULT;
           pub fn resolve(&self) -> HRESULT;
           pub fn set_security(&self) -> HRESULT;
           pub fn get_security(&self) -> HRESULT;
           pub fn get_registered_processes(&self) -> HRESULT;
           }
    }

    // 03837511-098b-11d8-9414-505054503030
    pub const CLSID_TRACE_DATA_PROV_COLLECTION: IID = IID {
        data1: 0x03837511,
        data2: 0x098b,
        data3: 0x11d8,
        data4: [0x94, 0x14, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30],
    };
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    pub fn test_get_provider() {
        unsafe {
            let guid =
                get_provider_guid("Microsoft-Windows-Kernel-Process").expect("Error Getting GUID");

            assert_eq!(GUID::from("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"), guid);
        }
    }

    #[test]
    pub fn test_provider_not_found() {
        unsafe {
            let err = get_provider_guid("Not-A-Real-Provider");

            assert_eq!(err, Err(PlaError::NotFound));
        }
    }
}
