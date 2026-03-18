//! Driver / Device objects.

use alloc::string::String;
use alloc::vec::Vec;
use super::irp::Irp;

pub type DispatchFn = fn(&mut Irp) -> i32;

pub struct DriverObject {
    pub name:      String,
    pub dispatch:  [Option<DispatchFn>; 28], // one per IRP_MJ_*
}

impl DriverObject {
    pub fn new(name: &str) -> Self {
        Self {
            name:     name.into(),
            dispatch: [None; 28],
        }
    }
}

pub struct DeviceObject {
    pub name:   String,
    pub driver: alloc::sync::Arc<spin::Mutex<DriverObject>>,
}
