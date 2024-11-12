use aya;
use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{perf::PerfEventArray, MapData};
use aya::util::online_cpus;
use bytes::BytesMut;

use super::event::Event;

const EVENT_BUFFERS_COUNT: usize = 10;

pub struct EventReader {
    perf_buffers: Vec<PerfEventArrayBuffer<MapData>>,
    event_buffers: Vec<BytesMut>,
}

impl EventReader {
    pub fn from_perf_array(perf_array: &mut PerfEventArray<MapData>) -> anyhow::Result<Self> {
        // Construct the per-core perf buffers
        let perf_buffers: Vec<PerfEventArrayBuffer<MapData>> = online_cpus()
            .map_err(|(_, error)| error)?
            .into_iter()
            .map(|cpu_id| perf_array.open(cpu_id, None).unwrap())
            .collect();
        // Construct the event buffering
        let event_buffers = (0..EVENT_BUFFERS_COUNT)
            .map(|_| BytesMut::with_capacity(std::mem::size_of::<Event>()))
            .collect();
        Ok(Self {
            perf_buffers,
            event_buffers,
        })
    }

    fn read_events_from_perf_buffer(
        event_buffers: &mut Vec<BytesMut>,
        perf_buffer: &mut PerfEventArrayBuffer<MapData>,
    ) -> Vec<Event> {
        let events = perf_buffer.read_events(event_buffers).unwrap();
        event_buffers
            .iter()
            .take(events.read)
            .map(|buf| {
                let event_ptr = buf.as_ptr() as *const Event;
                let event = unsafe { *event_ptr }; // Copy the event
                event
            })
            .collect::<Vec<_>>()
    }

    pub fn read_bulk(&mut self) -> Vec<Event> {
        self.perf_buffers
            .iter_mut()
            .flat_map(|perf_buffer| {
                Self::read_events_from_perf_buffer(&mut self.event_buffers, perf_buffer)
            })
            .collect()
    }
}
