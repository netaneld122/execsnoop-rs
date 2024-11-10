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
sudo RUST_LOG=info ./execsnoop
```

## Output example
```bash
[2024-11-10T09:09:36Z INFO  execsnoop] Waiting for Ctrl-C...
[2024-11-10T09:09:43Z INFO  execsnoop] [hit] execve pid:1816635 ts:1743067495540048 cmd:["-c=\"print('hi')\""]
[2024-11-10T09:09:45Z INFO  execsnoop] [hit] execve pid:1816635 ts:1743069885642674 cmd:["-c=\"print('hi')\""]
[2024-11-10T09:17:01Z INFO  execsnoop] [hit] execve pid:1816758 ts:1743505561262607 cmd:["run-parts", "--report", "/etc/cron.hourly"]
[2024-11-10T09:17:01Z INFO  execsnoop] [hit] execve pid:1816757 ts:1743505556385013 cmd:["/bin/sh", "-c", "   cd / && run-parts --report /etc/cron.hourly"]
```
