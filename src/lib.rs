
use aya;
use aya::maps::{perf::PerfEventArray, HashMap, MapData};
use aya::programs::TracePoint;

use procfs::process::Process;

use tokio::signal;
use tokio::time::{timeout, Duration};

use log::info;

mod event;
use event::Event;

mod event_reader;
use event_reader::EventReader;

struct Maps {
    events: PerfEventArray<MapData>,
    last_events: HashMap<MapData, u32, Event>,
}

impl Maps {
    fn from_ebpf(ebpf: &mut aya::Ebpf) -> anyhow::Result<Self> {
        let events = PerfEventArray::try_from(ebpf.take_map("events").unwrap())?;
        let last_events = HashMap::try_from(ebpf.take_map("last_events").unwrap())?;
        Ok(Self { events, last_events })
    }
}

pub struct Monitor {
    ebpf: aya::Ebpf,
}

impl Monitor {
    pub fn new() -> anyhow::Result<Self> {
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!("./bpf/execsnoop.bpf.o"))?;
        let program: &mut TracePoint = ebpf.program_mut("execve_hook").unwrap().try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;
        Ok(Self { ebpf })
    }

    pub async fn monitor_execve(&mut self) -> anyhow::Result<()> {
        let mut maps = Maps::from_ebpf(&mut self.ebpf)?;
        let mut reader = EventReader::from_perf_array(&mut maps.events).await?;
        loop {
            for event in reader.read_bulk().await {
                match Process::new(event.pid as i32) {
                    Ok(process) => {
                        let comm = std::str::from_utf8(&event.comm).unwrap_or("<unknown>");
                        let cmd = process.cmdline().unwrap_or_default();
                        let last_event = maps.last_events.get(&event.pid, 0).unwrap();
                        let marker = if event.timestamp == last_event.timestamp { "[hit]" } else { "[miss]" };
                        info!("{} execve pid:{} comm:{} cmd:{:?}", marker, event.pid, comm, cmd);
                    }
                    _ => info!("execve pid:{}", event.pid)
                }
            }
            if let Ok(_) = timeout(Duration::from_millis(1), signal::ctrl_c()).await {
                return Ok(())
            }
        }
    }
}
