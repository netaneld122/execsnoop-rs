# execsnoop-rs

Learning experience of writing execsnoop in Rust while leveraging eBPF.

## Implementation

* Load a simple eBPF program to hook a tracepoint on the `execve` syscall
* Stream `execve` events to a ring-buffer (using `BPF_MAP_TYPE_PERF_EVENT_ARRAY` for better compatibility with old kernels)
* Record the last `execve` event for each pid in a hash map (`BPF_MAP_TYPE_HASH`)
* Monitor from user-space
  * Read events from the perf array
  * Probe the `cmdline`, `exe` and `execfn` of the `pid` associated with the event
  * Make sure the last event in the hash map matches the one from the perf array, otherwise report that we missed `execve` events

## Environment
Currently, the Makefile is intended for cross-compilation on MacOS only.
```bash
make build
```

## Usage
Execute in a Linux machine:
```bash
sudo ./execsnoop
```

Usage is dead simple now:
```bash
Simple CLI tool to monitor execve() syscalls

Usage: execsnoop [OPTIONS]

Options:
  -d, --debug  Display error cases in more detail
  -h, --help   Print help
```

## Output example
```bash
[2024-11-14T19:52:40Z INFO  execsnoop] Waiting for Ctrl-C...
[2024-11-14T19:52:44Z INFO  execsnoop] ProcessClosed { pid: 1891880, comm: Some("bash") }
[2024-11-14T19:52:54Z INFO  execsnoop] ReadableProcessData {
        pid: 1891897,
        comm: "sshd",
        exe: "/usr/sbin/sshd",
        execfn: "/usr/sbin/sshd",
        cmdline: "",
    }
[2024-11-14T19:52:56Z INFO  execsnoop] ReadableProcessData {
        pid: 1891899,
        comm: "sshd",
        exe: "/usr/sbin/sshd",
        execfn: "<N/A>",
        cmdline: "sshd: vagrant [priv]",
    }
[2024-11-14T19:52:56Z INFO  execsnoop] ReadableProcessData {
        pid: 1891914,
        comm: "00-header",
        exe: "/usr/bin/dash",
        execfn: "/etc/update-motd.d/00-header",
        cmdline: "/bin/sh /etc/update-motd.d/00-header",
    }
[2024-11-14T19:52:56Z INFO  execsnoop] ReadableProcessData {
        pid: 1891906,
        comm: "run-parts",
        exe: "/usr/bin/dash",
        execfn: "/etc/update-motd.d/00-header",
        cmdline: "/bin/sh /etc/update-motd.d/00-header",
    }
```
