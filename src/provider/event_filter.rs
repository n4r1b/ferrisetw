use std::alloc::Layout;
use std::error::Error;

use windows::Win32::Foundation::BOOLEAN;
use windows::Win32::System::Diagnostics::Etw::{EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_PID, EVENT_FILTER_TYPE_EVENT_ID, EVENT_FILTER_EVENT_ID};
use windows::Win32::System::Diagnostics::Etw::{MAX_EVENT_FILTER_EVENT_ID_COUNT, MAX_EVENT_FILTER_PID_COUNT};

/// Specifies how this provider will filter its events
///
/// Some filters are not effective prior to Windows 8.1 ([source](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor#remarks))
#[derive(Debug)]
pub enum EventFilter {
    /// Filter by PID.
    /// This is only effective on kernel mode logger session.
    /// TODO: even for `KernelTrace`, this does not seem to work.
    ///       Maybe there's a distinction between "a trace run in kernel-mode" and a "System trace"?
    ///       See <https://github.com/n4r1b/ferrisetw/issues/51>
    ByPids(Vec<u16>),
    /// Filter by ETW Event ID.
    ByEventIds(Vec<u16>),
    // TODO: see https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
    //       and https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
    //       other filter types are possible
    //       I'm not always sure what they mean though
}

impl EventFilter {
    /// Builds an EventFilterDescriptor (which can in turn generate an EVENT_FILTER_DESCRIPTOR)
    pub fn to_event_filter_descriptor(&self) -> Result<EventFilterDescriptor, Box<dyn Error>> {
        match self {
            EventFilter::ByPids(pids) => EventFilterDescriptor::try_new_by_process_ids(pids),
            EventFilter::ByEventIds(ids) => EventFilterDescriptor::try_new_by_event_ids(ids),
        }
    }
}

/// Similar to windows' `EVENT_FILTER_DESCRIPTOR`, but with owned data
///
/// See [`Self::as_event_filter_descriptor`] to get a Windows-rs-compatible type
#[derive(Debug)]
pub struct EventFilterDescriptor {
    data: *mut u8,
    layout: Layout,
    ty: u32,
}

impl EventFilterDescriptor {
    /// Allocates a new instance, where the included data is `data_size` bytes, and is suitably aligned for type `T`
    fn try_new<T>(data_size: usize) -> Result<Self, Box<dyn Error>> {
        let data_size = match data_size {
            0 => return Err("Filter must not be empty".into()),
            1..=1024 => data_size as u32,
            _ => {
                // See https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
                return Err("Exceeded filter size limits".into())
            },
        };

        let layout = Layout::from_size_align(data_size as usize, std::mem::align_of::<T>())?;
        let data = unsafe {
            // Safety: layout size is non-zero
            std::alloc::alloc(layout)
        };
        if data.is_null() {
            return Err("Invalid allocation".into());
        }
        Ok(Self { data, layout, ty: 0 })
    }

    /// Build a new instance that will filter by event ID.
    ///
    /// Returns an `Err` in case the allocation failed, or if either zero or too many filter items were given
    pub fn try_new_by_event_ids(eids: &[u16]) -> Result<Self, Box<dyn Error>> {
        if eids.len() > MAX_EVENT_FILTER_EVENT_ID_COUNT as usize {
            // See https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
            return Err("Too many event IDs are filtered".into());
        }

        let data_size = std::mem::size_of::<EVENT_FILTER_EVENT_ID>() + (
            (eids.len().saturating_sub(1)) * std::mem::size_of::<u16>()
        );
        let mut s = Self::try_new::<EVENT_FILTER_EVENT_ID>(data_size)?;
        s.ty = EVENT_FILTER_TYPE_EVENT_ID;

        // Fill the data with an array of `EVENT_FILTER_EVENT_ID`s
        let p = s.data.cast::<EVENT_FILTER_EVENT_ID>();
        let mut p_evt = unsafe {
            (*p).FilterIn = BOOLEAN(1);
            (*p).Reserved = 0;
            (*p).Count = eids.len() as u16; // we've checked the array was less than 1024 items
            &((*p).Events[0]) as *const u16 as *mut u16
        };
        if eids.is_empty() {
            // Just to avoid an unintialized data, but should never be accessed anyway since p->Count = 0
            unsafe{
                *p_evt = 0;
            };
            return Ok(s);
        }

        for event_id in eids {
            unsafe{
                *p_evt = *event_id;
            };

            p_evt = unsafe {
                // Safety:
                // * both the starting and resulting pointer are within the same allocated object
                //   (except for the very last item, but that will not be written to)
                // * thus, the offset is smaller than an isize
                p_evt.offset(1)
            };
        }

        Ok(s)
    }

    /// Build a new instance that will filter by PIDs.
    ///
    /// Returns an `Err` in case the allocation failed, or if either zero or too many filter items were given
    pub fn try_new_by_process_ids(pids: &[u16]) -> Result<Self, Box<dyn Error>> {
        if pids.len() > MAX_EVENT_FILTER_PID_COUNT as usize {
            // See https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
            return Err("Too many PIDs are filtered".into());
        }

        let data_size = std::mem::size_of_val(pids); // PIDs are WORD, i.e. 16bits

        let mut s = Self::try_new::<u16>(data_size)?;
        s.ty = EVENT_FILTER_TYPE_PID;

        if pids.is_empty() {
            s.data = std::ptr::null_mut();
        } else {
            let mut p = s.data.cast::<u16>();
            for pid in pids {
                unsafe{
                    *p = *pid;
                };

                p = unsafe {
                    // Safety:
                    // * both the starting and resulting pointer are within the same allocated object
                    //   (except for the very last item, but that will not be written to)
                    // * thus, the offset is smaller than an isize
                    p.offset(1)
                };
            }
        }

        Ok(s)
    }

    /// Returns the EVENT_FILTER_DESCRIPTOR from this [`EventFilterDescriptor`]
    ///
    /// # Safety
    ///
    /// This will often be fed to an unsafe Windows function (e.g. [EnableTraceEx2](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)).
    /// Note that this contains pointers to the current `EventFilterDescriptor`, that must remain valid until the called function is done.
    pub fn as_event_filter_descriptor(&self) -> EVENT_FILTER_DESCRIPTOR {
        EVENT_FILTER_DESCRIPTOR {
            Ptr: self.data as u64,
            Size: self.layout.size() as u32,
            Type: self.ty,
        }
    }
}

impl Drop for EventFilterDescriptor {
    fn drop(&mut self) {
        unsafe{
            // Safety:
            // * ptr is a block of memory currently allocated via alloc::alloc
            // * layout is th one that was used to allocate that block of memory
            std::alloc::dealloc(self.data, self.layout);
        }
    }
}
