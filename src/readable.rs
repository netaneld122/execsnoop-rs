use execsnoop::{ExeRecord, ExecfnRecord, ExecveRecord};

#[allow(dead_code)]
#[derive(Debug)]
pub struct ReadableProcessData {
    pid: u32,
    comm: String,
    exe: String,
    execfn: String,
    filename: String,
    args: String,
}

const NOT_AVAILABLE: &str = "<N/A>";

impl From<ExecveRecord> for ReadableProcessData {
    fn from(record: ExecveRecord) -> Self {
        match record {
            ExecveRecord::ProcessData {
                pid,
                comm,
                exe,
                execfn,
                filename,
                args,
            } => ReadableProcessData {
                pid,
                comm: comm.unwrap_or(NOT_AVAILABLE.to_string()),
                exe: match exe {
                    ExeRecord::Reliable(path) => path
                        .map(|path| path.to_str().unwrap_or(NOT_AVAILABLE).to_owned())
                        .unwrap_or(NOT_AVAILABLE.to_string()),
                    _ => NOT_AVAILABLE.to_string(),
                },
                execfn: match execfn {
                    ExecfnRecord::Reliable(Some(execfn)) => execfn,
                    _ => NOT_AVAILABLE.to_string(),
                },
                filename,
                args: args.split("\0").collect::<Vec<_>>().join(" "),
            },
            _ => unreachable!(),
        }
    }
}
