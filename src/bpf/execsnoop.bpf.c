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

struct sys_enter_common_context {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
    int syscall_nr;
};

struct sys_enter_execve_context {
    struct sys_enter_common_context common;
    const char* filename;
    const char *const * argv;
    const char *const * envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_hook(struct sys_enter_execve_context* ctx)
{
    // Construct the event
    struct event event = {};
    int ret = 0;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
    if (ret < 0) {
        return 1;
    }

    // Read the filename
    ret = bpf_probe_read_user_str(event.filename, sizeof(event.filename), ctx->filename);
    if (ret < 0) {
       return 1;
    }

    // Read the arguments
    size_t offset = 0;
    const char* ptr;
    #pragma unroll
    for (size_t i = 0; i < 10; i++) {
        ret = bpf_probe_read_user(&ptr, sizeof(ptr), &ctx->argv[i]);
        if (ret < 0) {
            break;
        }
        // Need to make it clear for the verifier that offset + bytes_about_to_be_read < ARGS_LEN,
        // unfortunately it can't do simple arithmetic (i.e offset + ret < ARGS_LEN) so we need to statically
        // limit both to ARGS_LEN / 2.
        if (ptr == NULL || offset >= ARGS_LEN / 2) {
            break;
        }
        ret = bpf_probe_read_user_str(event.args + offset, ARGS_LEN / 2, ptr);
        if (ret < 0) {
            break;
        }
        offset += ret;
    }

    // Update the last_events map
    bpf_map_update_elem(&last_events, &event.pid, &event, BPF_ANY);

    // Send the event to user-space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // Print the event to /sys/kernel/debug/tracing/trace_pipe
    char msg[] = "execve\n";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
