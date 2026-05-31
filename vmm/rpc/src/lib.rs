// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

pub use generated::*;

mod generated;

impl GpuConfig {
    pub fn is_empty(&self) -> bool {
        if self.attach_mode == "all" {
            return false;
        }
        self.gpus.is_empty()
    }
}
