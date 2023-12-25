package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
)

var ifname string

func init() {
	flag.StringVar(&ifname, "ifname", "eth0", "interface name that ebpf program will be attached to")
	flag.Parse()
}

func main() {
	err := features.HaveProgramType(ebpf.XDP)
	if errors.Is(err, ebpf.ErrNotSupported) {
		fmt.Println("XDP program type is not supported")
		return
	}
	if err != nil {
		// Feature detection was inconclusive.
		panic(err)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it inot the kernel
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach xdp_xcounter to the network interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpXcounter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from xcounter_map.
	// exit the program when interrupted
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	protocols := []uint32{IPPROTO_TCP, IPPROTO_UDP}

	for {
		select {
		case <-tick:
			var count uint64

			for _, protocol := range protocols {
				err := objs.XcounterMap.Lookup(uint32(protocol), &count)
				if err != nil {
					log.Fatal("Map lookup: ", err)
				}
				if protocol == IPPROTO_TCP {
					log.Printf("Received %d TCP packets", count)
				} else {
					log.Printf("Received %d UDP packets", count)
				}
			}
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
