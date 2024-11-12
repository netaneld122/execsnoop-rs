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
[2024-11-12T11:40:04Z INFO  execsnoop] Waiting for Ctrl-C...
[2024-11-12T11:40:34Z INFO  execsnoop] ProcessData { pid: 1882584, comm: Some("sshd"), cmdline: Reliable(Ok(["/usr/sbin/sshd", "-D", "-R"])) }
[2024-11-12T11:40:37Z INFO  execsnoop] ProcessData { pid: 1882586, comm: Some("sshd"), cmdline: Reliable(Ok(["sshd: [accepted]"])) }
[2024-11-12T11:40:40Z INFO  execsnoop] ProcessData { pid: 1882588, comm: Some("sshd"), cmdline: Reliable(Ok(["sshd: vagrant [priv]"])) }
[2024-11-12T11:40:40Z INFO  execsnoop] ProcessData { pid: 1882590, comm: Some("sh"), cmdline: Reliable(Ok([])) }
[2024-11-12T11:40:40Z INFO  execsnoop] ProcessData { pid: 1882590, comm: Some("env"), cmdline: MissedSome(Ok(["/usr/bin/env", "-i", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "run-parts", "--lsbsysinit", "/etc/update-motd.d"])) }
[2024-11-12T11:40:40Z INFO  execsnoop] ProcessData { pid: 1882590, comm: Some("env"), cmdline: MissedSome(Ok(["/usr/bin/env", "-i", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "run-parts", "--lsbsysinit", "/etc/update-motd.d"])) }
[2024-11-12T11:40:40Z INFO  execsnoop] ProcessData { pid: 1882590, comm: Some("env"), cmdline: MissedSome(Ok(["/usr/bin/env", "-i", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "run-parts", "--lsbsysinit", "/etc/update-motd.d"])) }
[2024-11-12T11:40:40Z INFO  execsnoop] ProcessData { pid: 1882590, comm: Some("env"), cmdline: Reliable(Ok(["/usr/bin/env", "-i", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "run-parts", "--lsbsysinit", "/etc/update-motd.d"])) }
[2024-11-12T11:40:40Z INFO  execsnoop] ProcessData { pid: 1882601, comm: Some("run-parts"), cmdline: Reliable(Ok(["run-parts", "--lsbsysinit", "/etc/update-motd.d"])) }
```
