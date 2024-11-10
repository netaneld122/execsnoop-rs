
use aya;

const TASK_COMM_LEN: usize = 16;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub timestamp: u64,
    pub comm: [u8; TASK_COMM_LEN],
}

unsafe impl aya::Pod for Event {}
