#!/usr/bin/python3
from bcc import BPF
import ctypes as ct

program="""
struct user_msg_t { 
    char message[12];
};

BPF_HASH(config, u32, struct user_msg_t);

BPF_PERF_OUTPUT(output);

struct data_t { 
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int hello(void *ctx) {
    struct data_t data = {};
    struct user_msg_t *p;
    char message[12] = "Hello World";

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    
    p = config.lookup(&data.uid);
    if (p != 0) {
        bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
    } else {
        bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    }

    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root")
b["config"][ct.c_int(1000)] = ct.create_string_buffer(b"Hi user 1000!")

# the callback function
def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"pid: {data.pid} uid: {data.uid} {data.command.decode()} " + \
             f"{data.message.decode()}")
# open perf ring buffer, pass callback function which will be involked
b["output"].open_perf_buffer(print_event)

# poll the perf ring buffer indefinitely
while True:
    b.perf_buffer_poll()