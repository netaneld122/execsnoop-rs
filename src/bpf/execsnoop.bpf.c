#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} last_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_hook(struct trace_event_raw_sys_enter* ctx)
{
    // Send the event to user-space
    struct event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // Update the last_events map
    bpf_map_update_elem(&last_events, &event.pid, &event.timestamp, BPF_ANY);

    // Print the event to /sys/kernel/debug/tracing/trace_pipe
    char msg[] = "execve\n";
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk(msg, sizeof(msg), comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
