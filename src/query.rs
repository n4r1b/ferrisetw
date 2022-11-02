//! ETW information classes wrapper

use windows::Win32::System::Diagnostics::Etw::TRACE_PROFILE_INTERVAL;
use zerocopy::AsBytes;

use crate::{
    native::{etw_types::TraceInformation, evntrace},
    trace::TraceError,
};

type TraceResult<T> = Result<T, TraceError>;

#[repr(u32)]
pub enum ProfileSource {
    ProfileTime = 0,
}

pub struct SessionlessInfo;

impl SessionlessInfo {
    pub fn sample_interval(source: ProfileSource) -> TraceResult<u32> {
        let mut info = TRACE_PROFILE_INTERVAL {
            Source: source as u32,
            Interval: 0,
        };

        evntrace::query_info(
            TraceInformation::TraceSampledProfileIntervalInfo,
            // SAFETY: TRACE_PROFILE_INTERVAL is `#[repr(C)]` and uses only POD
            unsafe {
                std::slice::from_raw_parts_mut(
                    &mut info as *mut _ as *mut u8,
                    std::mem::size_of::<TRACE_PROFILE_INTERVAL>(),
                )
            },
        )?;

        Ok(info.Interval)
    }

    pub fn max_pmc() -> TraceResult<u32> {
        let mut max_pmc = 0u32;

        evntrace::query_info(
            TraceInformation::TraceMaxPmcCounterQuery,
            max_pmc.as_bytes_mut(),
        )?;

        Ok(max_pmc)
    }
}
