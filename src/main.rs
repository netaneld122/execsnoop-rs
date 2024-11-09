use procfs::process::Process;
use aya::programs::TracePoint;
use aya::maps::{perf::PerfEventArray, HashMap, MapData};
use tokio::signal;
use tokio::time::{timeout, Duration};

use execsnoop::EventReader;

async fn monitor_perf_event_array(
    perf_array: &mut PerfEventArray<MapData>,
    last_events: &HashMap<MapData, u32, u64>,
) -> anyhow::Result<()> {
    let mut reader = EventReader::from_perf_array(perf_array).await?;
    loop {
        for event in reader.read_bulk().await {
            match Process::new(event.pid as i32) {
                Ok(process) => {
                    let cmd = process.cmdline().unwrap_or_default();
                    let last_timestamp = last_events.get(&event.pid, 0).unwrap_or_default();
                    let marker = if event.timestamp == last_timestamp { "[HIT]" } else { "[MISS]" };
                    println!("{} execve pid:{} ts:{} cmd:{:?}", marker, event.pid, event.timestamp, cmd);
                }
                _ => println!("execve pid:{} ts:{}", event.pid, event.timestamp)
            }
        }
        if let Ok(_) = timeout(Duration::from_millis(1), signal::ctrl_c()).await {
            return Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // Load and attach the BPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!("./bpf/execsnoop.bpf.o"))?;
    let program: &mut TracePoint = ebpf.program_mut("execve_hook").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // Open the perf event array and read events
    let mut perf_array = PerfEventArray::try_from(ebpf.take_map("events").unwrap())?;
    // Open the last events map
    let last_events = HashMap::try_from(ebpf.take_map("last_events").unwrap())?;
    println!("Waiting for Ctrl-C...");
    monitor_perf_event_array(&mut perf_array, &last_events).await?;

    println!("Exiting...");
    Ok(())
}
