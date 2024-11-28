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
    __type(value, struct event);
} last_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_hook_enter(struct trace_event_raw_sys_enter* ctx)
{
    // Construct the event
    struct event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    int ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
    if (ret < 0) {
        return 1;
    }

    // Update the last_events map
    ret = bpf_map_update_elem(&last_events, &event.pid, &event, BPF_ANY);
    if (ret < 0) {
        return 1;
    }

    // Trace the event to /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("execve enter");
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int execve_hook_exit(struct trace_event_raw_sys_exit* ctx)
{
    // Get the event from the last_events map
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct event* event = bpf_map_lookup_elem(&last_events, &pid);
    if (event == NULL) {
        return 0;
    }

    // Send the event to user-space
    int ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));
    if (ret < 0) {
        return 1;
    }

    // Trace the event to /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("execve exit");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
