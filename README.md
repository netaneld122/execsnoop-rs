# execsnoop-rs

Learning experience of writing execsnoop in Rust while leveraging eBPF.

## Implementation

* Load a simple eBPF program to hook a tracepoint on the `execve` syscall
* Stream `execve` events to a ring-buffer (using `BPF_MAP_TYPE_PERF_EVENT_ARRAY` for better compatibility with old kernels)
* Record the last `execve` event for each pid in a hash map (`BPF_MAP_TYPE_HASH`)
* Monitor from user-space
  * Read events from the perf array
  * Probe the `cmdline` of the `pid` associated with the event
  * Make sure the last event in the hash map matches the one from the perf array, otherwise report that we missed `execve` events

## Environment
Currently, the Makefile is intended for cross-compilation on MacOS only.
```bash
make build
```

Execute in a Linux machine:
```bash
sudo ./execsnoop
```

## Output example
```bash
[2024-11-11T09:28:57Z INFO  execsnoop] Waiting for Ctrl-C...
[2024-11-11T09:28:59Z INFO  execsnoop] ProcessData { pid: 1820391, comm: Some("bash"), cmdline: Reliable(Ok(["watch", "-n", "-1", "ls"])) }
[2024-11-11T09:28:59Z INFO  execsnoop] ProcessData { pid: 1820393, comm: Some("watch"), cmdline: Reliable(Ok(["sh", "-c", "ls"])) }
[2024-11-11T09:28:59Z INFO  execsnoop] ProcessData { pid: 1820394, comm: Some("sh"), cmdline: Reliable(Ok(["sh", "-c", "ls"])) }
[2024-11-11T09:28:59Z INFO  execsnoop] ProcessData { pid: 1820396, comm: Some("watch"), cmdline: Reliable(Ok(["watch", "-n", "-1", "ls"])) }
[2024-11-11T09:28:59Z INFO  execsnoop] ProcessData { pid: 1820397, comm: Some("sh"), cmdline: Reliable(Ok(["sh", "-c", "ls"])) }
```
