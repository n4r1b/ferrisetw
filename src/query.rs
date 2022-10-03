//! ETW information classes wrapper

use windows::Win32::System::Diagnostics::Etw::TRACE_PROFILE_INTERVAL;

use memoffset::offset_of;
use std::convert::TryInto;
use zerocopy::{AsBytes, FromBytes};

use crate::{
    native::{etw_types::TraceInformation, evntrace},
    trace::TraceError,
};

type TraceResult<T> = Result<T, TraceError>;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod ffi {
    #[repr(C)]
    #[derive(zerocopy::AsBytes, zerocopy::FromBytes)]
    pub struct PROFILE_SOURCE_INFO {
        pub NextEntryOffset: u32,
        pub Source: u32,
        pub MinInterval: u32,
        pub MaxInterval: u32,
        pub Reserved: u64,
        pub Description: [u16; 4], // Sized until next entry
    }
}

#[repr(u32)]
pub enum ProfileSource {
    ProfileTime = 0,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSourceInfo {
    pub id: u32,
    pub min_interval: u32,
    pub max_interval: u32,
    pub description: String,
}

pub struct SessionInfo<'a>(&'a mut evntrace::NativeEtw);

impl SessionInfo<'_> {}

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

    pub fn profile_sources() -> TraceResult<Vec<ProfileSourceInfo>> {
        let mut memblk = [0u8; 8192];
        let mut memblk = {
            let len =
                evntrace::query_info(TraceInformation::TraceProfileSourceListInfo, &mut memblk)?;
            &memblk[..len]
        };

        let mut sources = Vec::new();

        while !memblk.is_empty() {
            let source_info = match ffi::PROFILE_SOURCE_INFO::read_from_prefix(memblk) {
                Some(si) => si,
                None => break,
            };

            let desc_end = match source_info.NextEntryOffset {
                0 => memblk.len(),
                n => n as usize,
            };

            let desc = &memblk[offset_of!(ffi::PROFILE_SOURCE_INFO, Description)..desc_end];
            let desc = desc
                .chunks_exact(2)
                // Filter out the NULL terminator.
                .filter_map(|c| match u16::from_ne_bytes(c.try_into().unwrap()) {
                    0 => None,
                    n => Some(n),
                })
                .collect::<Vec<_>>();

            sources.push(ProfileSourceInfo {
                id: source_info.Source,
                min_interval: source_info.MinInterval,
                max_interval: source_info.MaxInterval,
                description: String::from_utf16_lossy(&desc),
            });

            if source_info.NextEntryOffset == 0 {
                break;
            }

            memblk = &memblk[source_info.NextEntryOffset as usize..];
        }

        Ok(sources)
    }
}
