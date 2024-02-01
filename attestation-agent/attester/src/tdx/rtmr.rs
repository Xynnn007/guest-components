// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

/// The actual rtmr event data handled in DCAP
#[repr(C, packed)]
pub struct TdxRtmrEvent {
    /// Always 1
    version: u32,

    /// The RTMR that will be extended.
    /// As defined in https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#td-measurement
    /// we will use RTMR 2 for guest application code and configuration.
    rtmr_index: u64,

    /// Data that will be used to extend RTMR
    extend_data: [u8; 48usize],

    /// Not used in DCAP
    event_type: u32,

    /// Always 0
    event_data_size: u32,

    /// Not used in DCAP
    event_data: Vec<u8>,
}

impl Default for TdxRtmrEvent {
    fn default() -> Self {
        Self {
            extend_data: [0; 48],
            version: 1,
            rtmr_index: 2,
            event_type: 0,
            event_data_size: 0,
            event_data: Vec::new(),
        }
    }
}

impl TdxRtmrEvent {
    pub fn with_extend_data(mut self, extend_data: [u8; 48]) -> Self {
        self.extend_data = extend_data;
        self
    }

    pub fn with_rtmr_index(mut self, rtmr_index: u64) -> Self {
        self.rtmr_index = rtmr_index;
        self
    }
}

impl Into<Vec<u8>> for TdxRtmrEvent {
    fn into(self) -> Vec<u8> {
        let event_ptr = &self as *const TdxRtmrEvent as *const u8;
        let event_data_size = std::mem::size_of::<u8>() * self.event_data_size as usize;
        let res_size = std::mem::size_of::<u32>() * 3
            + std::mem::size_of::<u64>()
            + std::mem::size_of::<[u8; 48]>()
            + event_data_size;
        let mut res = vec![0; res_size];
        unsafe {
            for i in 0..res_size - event_data_size {
                res[i] = *event_ptr.add(i);
            }
        }
        let event_data = Vec::from(self.event_data);
        for i in 0..event_data_size {
            res[i + res_size - event_data_size] = event_data[i];
        }

        return res;
    }
}
