use procfs::process::Process;
use aya::programs::TracePoint;
use aya::maps::{perf::PerfEventArray, HashMap, MapData};
use tokio::signal;
use tokio::time::{timeout, Duration};
use log::{info, error};
use env_logger;

use execsnoop::{Event, EventReader};

async fn monitor_execve(
    perf_array: &mut PerfEventArray<MapData>,
    last_events: &HashMap<MapData, u32, Event>,
) -> anyhow::Result<()> {
    let mut reader = EventReader::from_perf_array(perf_array).await?;
    loop {
        for event in reader.read_bulk().await {
            match Process::new(event.pid as i32) {
                Ok(process) => {
                    let cmd = process.cmdline().unwrap_or_default();
                    let last_event = last_events.get(&event.pid, 0).unwrap();
                    let marker = if event.timestamp == last_event.timestamp { "[hit]" } else { "[miss]" };
                    info!("{} execve pid:{} ts:{} cmd:{:?}", marker, event.pid, event.timestamp, cmd);
                }
                _ => info!("execve pid:{} ts:{}", event.pid, event.timestamp)
            }
        }
        if let Ok(_) = timeout(Duration::from_millis(1), signal::ctrl_c()).await {
            return Ok(())
        }
    }
}

fn set_memlock_limit_for_old_kernels() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        error!("remove limit on locked memory failed, ret is: {}", ret);
    }
}

fn load_ebpf_program() -> anyhow::Result<aya::Ebpf> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!("./bpf/execsnoop.bpf.o"))?;
    let program: &mut TracePoint = ebpf.program_mut("execve_hook").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    Ok(ebpf)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    set_memlock_limit_for_old_kernels();

    let mut ebpf = load_ebpf_program()?;

    // Open the perf event array to read events
    let mut events: PerfEventArray<MapData> = PerfEventArray::try_from(ebpf.take_map("events").unwrap())?;

    // Open the last events map to keep track of the last event timestamp
    let last_events = HashMap::try_from(ebpf.take_map("last_events").unwrap())?;

    // Start monitoring
    info!("Waiting for Ctrl-C...");
    monitor_execve(&mut events, &last_events).await?;

    info!("Exiting...");
    Ok(())
}
