const TASK_COMM_LEN: usize = 16;
const MAX_PATH: usize = 100;
const ARGS_LEN: usize = 200;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub timestamp: u64,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_PATH],
    pub args: [u8; ARGS_LEN],
}

unsafe impl aya::Pod for Event {}
