
use aya;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub timestamp: u64,
    pub comm: [u8; 16],
}

unsafe impl aya::Pod for Event {}
