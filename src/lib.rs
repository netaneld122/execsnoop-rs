
use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{perf::PerfEventArray, MapData};
use aya::util::online_cpus;
use bytes::BytesMut;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub timestamp: u64,
}

const EVENT_BUFFERS_COUNT: usize = 10;

pub struct EventReader {
    perf_buffers: Vec<PerfEventArrayBuffer<MapData>>,
    event_buffers: Vec<BytesMut>,
}

impl EventReader{
    pub async fn from_perf_array(perf_array: &mut PerfEventArray<MapData>) -> anyhow::Result<Self> {
        let mut perf_buffers = Vec::new();
        for cpu_id in online_cpus().map_err(|(_, error)| error)? {
            // this perf buffer will receive events generated on the CPU with id cpu_id
            perf_buffers.push(perf_array.open(cpu_id, None)?);
        }
        let event_buffers = (0..EVENT_BUFFERS_COUNT).map(
            |_| BytesMut::with_capacity(std::mem::size_of::<Event>())
        ).collect();
        Ok(Self {
            perf_buffers,
            event_buffers,
        })
    }

    pub async fn read_bulk(&mut self) -> Vec<Event> {
        let mut all_events = Vec::new();
        for perf_buffer in self.perf_buffers.iter_mut() {
            let events = perf_buffer.read_events(&mut self.event_buffers).unwrap();
            all_events.extend(self.event_buffers.iter().take(events.read).map(|buf| {
                let event_ptr = buf.as_ptr() as *const Event;
                let event = unsafe { *event_ptr }; // Copy the event
                event
            }));
        }
        all_events
    }
}
