use crate::readable::ReadableProcessData;
use clap::{arg, Parser};
use execsnoop::{self, ExecveRecord};
use log::{error, info};
use tokio::{self, signal};

mod readable;

fn set_memlock_rlimit_for_old_kernels() {
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

const DEFAULT_LOGGING_LEVEL: &str = "info";

fn setup_logger() {
    let env = env_logger::Env::default().default_filter_or(DEFAULT_LOGGING_LEVEL);
    env_logger::Builder::from_env(env).init();
}

/// Simple CLI tool to monitor execve() syscalls
#[derive(Parser)]
struct Cli {
    /// Display error cases in more detail
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    setup_logger();

    set_memlock_rlimit_for_old_kernels();

    info!("Waiting for Ctrl-C...");
    let ctrl_c = tokio::spawn(signal::ctrl_c());

    // Start monitoring
    let monitor = execsnoop::Monitor::new()?;
    for record in monitor {
        match record {
            ExecveRecord::ProcessData { .. } => {
                if cli.debug {
                    info!("{:?}", record);
                } else {
                    info!("{:#?}", ReadableProcessData::from(record));
                }
            }
            ExecveRecord::None => (),
            _ => {
                info!("{:?}", record);
            }
        }
        if ctrl_c.is_finished() {
            break;
        }
    }

    info!("Exiting...");
    Ok(())
}
