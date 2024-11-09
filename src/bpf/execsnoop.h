#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    __u64 timestamp;
};

#endif /* __EXECSNOOP_H */
