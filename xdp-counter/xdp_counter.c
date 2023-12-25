#include "xdp_counter.bpf.skel.h"
#include <bpf/libbpf.h>
#include <linux/in.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>

bool is_shutdown = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_sigint(int signum) {
    printf("Shutting down xdp_counter\n");
    is_shutdown = true;
}

__u32 *u8Ptr(__u32 val) {
    __u32 *valPtr = (__u32 *)malloc(sizeof(__u32));
    *valPtr = val;
    return valPtr;
}

int main(int argc, char **argv) {
    struct xdp_counter_bpf *skel;
    struct bpf_link *link;
    int ifindex;
    char ifname[10] = "enp0s3";

    if (argc > 1) {
        strcpy(ifname, argv[1]);
    }

    libbpf_set_print(libbpf_print_fn);

    skel = xdp_counter_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open and load BPF skeleton\n");
        return 1;
    }
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index\n");
        return 1;
    }
    
    link = bpf_program__attach_xdp(skel->progs.xdp_xcounter, ifindex);
    if (libbpf_get_error(link)) {
        printf("Failed to attach BPF program to interface %d\n", ifindex);
        xdp_counter_bpf__destroy(skel);
        return 1;
    }
    // int err = xdp_counter_bpf__attach(skel);
    // if (err != 0) {
    //     fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    //     xdp_counter_bpf__destroy(skel);
    //     return 1;
    // }

    int protocols[] = { IPPROTO_TCP, IPPROTO_UDP };
    long *value = (long *)malloc(sizeof(long));

    signal(SIGINT, handle_sigint);
    while (true) {
        sleep(1);
        if (is_shutdown) {
            break;
        }

        for (int i = 0; i < sizeof(protocols)/sizeof(IPPROTO_TCP); i++) {
            int err = bpf_map__lookup_elem(skel->maps.xcounter_map, u8Ptr((__u32)protocols[i]), sizeof(__u32), value, sizeof(value), BPF_ANY);
            if (err != 0) {
                printf("Error reading counter map, return code: %d\n", err);
                return 1;
            } else if (*value != 0) {
                if (protocols[i] == IPPROTO_TCP) {
                    printf("TCP packets: %lu\n", *value); 
                } else if (protocols[i] == IPPROTO_UDP) {
                    printf("UDP packets: %lu\n", *value); 
                }
            }
        }
    }

    xdp_counter_bpf__destroy(skel);
    printf("Shuted down ebpf program\n");
    return 0;
}