
use aya;
use aya::maps::{perf::PerfEventArray, HashMap, MapData};
use aya::programs::TracePoint;

use procfs::process::Process;

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
        Ok(Self {
            events: PerfEventArray::try_from(ebpf.take_map("events").unwrap())?,
            last_events: HashMap::try_from(ebpf.take_map("last_events").unwrap())?,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct MonitorRecordData {
    pid: u32,
    comm: Option<String>,
    cmdline: Option<Vec<String>>,
}

#[derive(Debug)]
pub enum MonitorRecord {
    Hit(MonitorRecordData),
    Miss(MonitorRecordData),
    ProcessClosed{ pid: u32 },
    Nop,  // We refrain from blocking the iterator, so when no new events are available, we return this
}

pub struct Monitor {
    ebpf: aya::Ebpf,
}

fn event_to_record(event: &Event, maps: &Maps) -> MonitorRecord {
    match Process::new(event.pid as i32) {
        Ok(process) => {
            let cmdline = process.cmdline().ok();
            let last_event = maps.last_events.get(&event.pid, 0).unwrap();
            let record_data = MonitorRecordData {
                pid: event.pid,
                comm: std::str::from_utf8(&event.comm).ok().map(|s| s.trim_end_matches('\0').to_string()),
                cmdline,
            };
            if event.timestamp == last_event.timestamp {
                MonitorRecord::Hit(record_data)
            } else {
                MonitorRecord::Miss(record_data)
            }
        }
        _ => MonitorRecord::ProcessClosed{ pid: event.pid },
    }
}

impl Monitor {
    pub fn new() -> anyhow::Result<Self> {
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!("./bpf/execsnoop.bpf.o"))?;
        let program: &mut TracePoint = ebpf.program_mut("execve_hook").unwrap().try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;
        Ok(Self { ebpf })
    }

    pub fn into_iter(&mut self) -> impl Iterator<Item=MonitorRecord> {
        let mut maps = Maps::from_ebpf(&mut self.ebpf).expect("Failed to load maps");
        let mut reader = EventReader::from_perf_array(&mut maps.events).expect("Failed to read from perf array");
        std::iter::from_fn(move || {
            Some(reader.read_bulk().into_iter().map(|event| event_to_record(&event, &maps)).collect::<Vec<_>>())
        }).flat_map(|v|if v.len() == 0 { vec![MonitorRecord::Nop] } else { v })
    }
}

