#ifndef __XCOUNTER_H__
#define __XCOUNTER_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#define __x86_64__ 1

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <bpf/bpf_helpers.h>

#define XCOUNTER_MAP_SIZE 256

// Forward declaration
static int parse_ipv4(void *data, void *data_end);
static int parse_ipv6(void *data, void *data_end);

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __XCOUNTER_H__ */