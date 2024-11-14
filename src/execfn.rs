use std::os::unix::fs::FileExt;

use procfs::process::Process;

const AT_EXECFN: u64 = 31;
const PATH_MAX: usize = 4096;

pub fn get_process_execfn(pid: u32) -> anyhow::Result<String> {
    // Get the AT_EXECFN address from the process's auxiliary vector
    let process = Process::new(pid as i32)?;
    let execfn_address = *process
        .auxv()?
        .get(&AT_EXECFN)
        .ok_or(anyhow::anyhow!("AT_EXECFN not found"))?;

    // Read the execfn buffer from the process's memory
    let process_memory = process.mem()?;
    let mut buf = [0u8; PATH_MAX];
    process_memory.read_at(&mut buf, execfn_address)?;

    // Convert to a String
    Ok(std::str::from_utf8(&buf)?.trim_end_matches('\0').into())
}
