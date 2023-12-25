//go:build ignore

#ifndef __XCOUNTER_H__
#define __XCOUNTER_H__

#define __x86_64__ 1

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <bpf/bpf_helpers.h>

#define XCOUNTER_MAP_SIZE 256

// Forward declaration
static int parse_ipv4(void *data, void *data_end);
static int parse_ipv6(void *data, void *data_end);

#endif /* __XCOUNTER_H__ */