#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16
#define MAX_PATH 100
#define ARGS_LEN 200

struct event {
    __u32 pid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH];
    char args[ARGS_LEN];
};

#endif /* __EXECSNOOP_H */
