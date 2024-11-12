use aya;
use aya::maps::{perf::PerfEventArray, HashMap, MapData};
use aya::programs::TracePoint;

use procfs::process::Process;
use procfs::ProcResult;

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

#[derive(Debug)]
pub enum CmdlineRecord {
    Reliable(ProcResult<Vec<String>>),
    MissedSome(ProcResult<Vec<String>>),
}

#[derive(Debug)]
pub enum ExecveRecord {
    ProcessData {
        pid: u32,
        comm: Option<String>,
        cmdline: CmdlineRecord,
    },
    ProcessClosed {
        pid: u32,
    },
    None, // We refrain from blocking the iterator, so when no new events are available, we return this
}

pub struct Monitor {
    ebpf: aya::Ebpf,
}

fn event_to_record(event: &Event, maps: &Maps) -> ExecveRecord {
    match Process::new(event.pid as i32) {
        Ok(process) => {
            let cmdline = process.cmdline();
            let last_event = maps.last_events.get(&event.pid, 0).unwrap();
            let cmdline = if event.timestamp == last_event.timestamp {
                CmdlineRecord::Reliable(cmdline)
            } else {
                CmdlineRecord::MissedSome(cmdline)
            };
            ExecveRecord::ProcessData {
                pid: event.pid,
                comm: std::str::from_utf8(&event.comm)
                    .ok()
                    .map(|s| s.trim_end_matches('\0').to_string()),
                cmdline,
            }
        }
        _ => ExecveRecord::ProcessClosed { pid: event.pid },
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
}

pub struct MonitorIterator {
    // Unfortunately the aya crate doesn't handle lifetimes well, so we need to keep the Ebpf instance around to keep the maps alive
    #[allow(dead_code)]
    ebpf: aya::Ebpf,
    pub iter: Box<dyn Iterator<Item = ExecveRecord>>,
}

impl Iterator for MonitorIterator {
    type Item = ExecveRecord;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl IntoIterator for Monitor {
    type Item = ExecveRecord;
    type IntoIter = MonitorIterator;

    fn into_iter(mut self) -> Self::IntoIter {
        let mut maps = Maps::from_ebpf(&mut self.ebpf).expect("Failed to load maps");
        let mut reader =
            EventReader::from_perf_array(&mut maps.events).expect("Failed to read from perf array");

        // Flatten the event bulks into individual records
        let iter = std::iter::from_fn(move || {
            Some(
                reader
                    .read_bulk()
                    .into_iter()
                    .map(|event| event_to_record(&event, &maps))
                    .collect::<Vec<_>>(),
            )
        })
        .flat_map(|v| {
            if v.len() == 0 {
                vec![ExecveRecord::None]
            } else {
                v
            }
        });

        // The iterator we're creating here is too complex to be expressed as an associated type in Iterator/IntoIterator (type_alias_impl_trait isn't stable yet),
        // so we wrap it in a Box and reference it dynamically by the trait object.
        MonitorIterator {
            ebpf: self.ebpf,
            iter: Box::new(iter),
        }
    }
}
