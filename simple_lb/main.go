package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	awsclient "simple-lb/pkg/aws"
	"simple-lb/pkg/config"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Listener struct {
	Protocol    string `json:"protocol"`
	Port        uint16 `json:"port"`
	DestPort    uint16 `json:"destPort"`
	IdleTimeOut string `json:"idleTimeout,omitempty"`
}

type ListenerConfig struct {
	Listener []Listener `json:"listeners"`
}

var mainConfig *config.Config = config.NewConfig()
var listenerConfig ListenerConfig

func init() {
	config.ParseCli(mainConfig)

	if mainConfig.AWSProfile == "" {
		panic(errors.New("aws-profile must be specified with --aws-profile command line argument or AWS_PROFILE environment variable"))
	}

	if mainConfig.AutoScalingGroupName == "" && mainConfig.AWSTag.IsZero() {
		panic(errors.New("at least one of the aws-scaling-group-name or aws-tag must be specified or both, the program prioritises the former"))
	}

	// Load listener
	content, err := os.ReadFile(mainConfig.ListenerConfigFile)
	if err != nil {
		panic(fmt.Errorf("cannot read listener config file %s: %s", mainConfig.ListenerConfigFile, err.Error()))
	}
	if err := json.Unmarshal(content, &listenerConfig); err != nil {
		panic(fmt.Errorf("cannot unmarshal listener config %s: ", err.Error()))
	}

}

func main() {
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs simple_lbObjects
	if err := loadSimple_lbObjects(&objs, nil); err != nil {
		log.Fatal("Loadding eBPF objects: ", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(mainConfig.InterfaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", mainConfig.InterfaceName, err)
	}

	// Attach simple_lb to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.SimpleLb,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP: ", err)
	}
	defer link.Close()

	// get EC2 IP addresses
	// awsClient, err := awsclient.NewAWSClient(&mainConfig.AWSProfile)
	// if err != nil {
	// 	log.Fatal("Cannot new an AWSClient instance: ", err)
	// }

	// instanceIDs := []string{}

	// if len(mainConfig.AutoScalingGroupName) > 0 {
	// 	instanceIDs, err = awsClient.GetInstanceIDs(ctx, mainConfig.AutoScalingGroupName)
	// 	if err != nil {
	// 		log.Fatalf("Get instance ids of auto scaling group %s failed: %s", mainConfig.AutoScalingGroupName, err.Error())
	// 	} else if len(instanceIDs) == 0 {
	// 		log.Default().Printf("Not found any instances belonging to auto scaling group: %s\n", mainConfig.AutoScalingGroupName)
	// 	}
	// }

	// var tags []ec2type.Tag
	// if !mainConfig.AWSTag.IsZero() {
	// 	for _, value := range mainConfig.AWSTag.Values {
	// 		tags = append(tags, ec2type.Tag{
	// 			Key:   &mainConfig.AWSTag.Key,
	// 			Value: stringPtr(value),
	// 		})
	// 	}
	// }

	// if len(instanceIDs) == 0 && len(tags) == 0 {
	// 	log.Fatal("Not found any instancesIDs and tags is not specified, please check again")
	// }

	// Setup listener
	for _, listener := range listenerConfig.Listener {
		keyInBytes := make([]byte, 4)

		if strings.ToLower(listener.Protocol) != "tcp" {
			log.Default().Print("load balancer only support TCP listener", listener)
			continue
		}

		keyInBytes[0] = syscall.IPPROTO_TCP
		keyInBytes[2] = byte(listener.Port)
		keyInBytes[3] = byte(listener.Port >> 8)

		idleTimeout, err := time.ParseDuration(listener.IdleTimeOut)
		if err != nil {
			log.Default().Print("can not parse duration", listener, err)
			continue
		}
		if idleTimeout.Seconds() > 65535 {
			log.Default().Println("load balancer do not support idle timeout > 2^16 - 1")
			continue
		}

		valueInBytes := make([]byte, 4)
		valueInBytes[0] = byte(listener.DestPort)
		valueInBytes[1] = byte(listener.DestPort >> 8)
		valueInBytes[2] = byte(idleTimeout.Seconds())
		valueInBytes[3] = byte(uint16(idleTimeout.Seconds()) >> 8)
		if err := objs.ListenersMap.Put(keyInBytes, valueInBytes); err != nil {
			log.Fatal("Cannot put listener with error: ", err)
		}
	}

	// var instanceAddresses []awsclient.InstanceAddress
	// var shutdown chan interface{}

	// go func() {
	// 	for {
	// 		timer := time.NewTimer(time.Minute)
	// 		select {
	// 		case <-shutdown:
	// 			timer.Stop()
	// 			return
	// 		case <-timer.C:
	// 			instanceAddresses, err = awsClient.GetPrivateAddress(ctx, instanceIDs, tags)
	// 			if err != nil {
	// 				log.Fatal("Cannot get private address with error: ", err)
	// 			}
	// 		}
	// 	}
	// }()

	// instanceAddresses, err = awsClient.GetPrivateAddress(ctx, instanceIDs, tags)
	// if err != nil {
	// 	log.Fatal("Cannot get private address with error: ", err)
	// }

	instanceAddresses := []awsclient.InstanceAddress{
		{
			InstanceID: "i-1xxx",
			IPAddress:  "172.30.2.107",
			MacAdress:  "50:eb:f6:5c:d6:48",
		},
	}

	if len(instanceAddresses) > 0 {
		for _, instance := range instanceAddresses {
			ip := net.ParseIP(instance.IPAddress)
			if ip == nil {
				log.Default().Printf("Invalid ip address %s\n", instance.IPAddress)
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				log.Default().Printf("ip is not an IPv4 address: %s\n", ip)
				continue
			}

			mac, err := net.ParseMAC(instance.MacAdress)
			if err != nil {
				log.Default().Printf("Invalid mac address %s\n", instance.MacAdress)
				continue
			}
			if err := objs.ArpTablesMap.Put(ip4, mac); err != nil {
				log.Default().Println("cannot put or update mac address with error: ", err)
				continue
			}

			if err := objs.UpstreamsMap.Put(nil, ip4); err != nil {
				log.Default().Printf("Cannot put ip %s to Upstream Map: %s\n", ip4, err.Error())
				if err = objs.ArpTablesMap.Delete(ip4); err != nil {
					log.Default().Printf("Cannot remove mac address %s of ip %s from Upstream Map: %s\n", mac, ip4, err.Error())
				}
			}
			fmt.Printf("Put IP %s to upstream map\n", ip4)
		}
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// shutdown := make(chan struct{}, 1)

	sig := <-sigs
	log.Default().Printf("Received signal: %s, exiting...", sig)
}

func stringPtr(s string) *string { return &s }
