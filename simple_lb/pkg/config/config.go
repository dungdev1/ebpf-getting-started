package config

import (
	"flag"
	"log"
	"os"
)

type Config struct {
	AutoScalingGroupName string
	AWSTag               Tag
	AWSProfile           string
	InterfaceName        string
	ListenerConfigFile   string
}

const (
	AWSProfileKey           = "PROFILE"
	AWSTagKey               = "TAG"
	AutoScalingGroupNameKey = "AWS_AUTO_SCALING_GROUP_NAME"
	NetworkInterfaceNameKey = "IF_NAME"
	ListenerConfigFileKey   = "LISTENER_CONFIG"
	ListenerConfigFileValue = "/etc/simple-elb/listener.conf.json"
)

func ParseCli(config *Config) {
	flag.StringVar(&config.AWSProfile, "aws-profile", getStringEnv(AWSProfileKey, ""), "aws profile to interact with AWS API")
	flag.Var(&config.AWSTag, "aws-tag", "tags list to filter ec2 instances")
	flag.StringVar(&config.AutoScalingGroupName, "aws-scaling-group-name", getStringEnv(AutoScalingGroupNameKey, ""), "aws auto scaling group used to getting the list of ec2 instances")
	flag.StringVar(&config.InterfaceName, "ifname", getStringEnv(NetworkInterfaceNameKey, "eth0"), "network interface name that ebpf program attached to (default is eth0)")
	flag.StringVar(&config.ListenerConfigFile, "listener-config-path", getStringEnv(ListenerConfigFileKey, ListenerConfigFileValue), "listener config file providing listener supported")

	flag.Parse()
}

func (config *Config) PrintHumanConfigArgs() {
	log.Default().Printf("Load balancer configuration: \n"+
		"\taws-profile: %s,\n"+
		"\aws-tag: %s\n"+
		"\taws-scaling-group-name: %s\n",
		config.AWSProfile,
		config.AWSTag.String(),
		config.AutoScalingGroupName)
}

func NewConfig() *Config {
	return &Config{}
}

func getStringEnv(key, fallback string) string {
	if envVar, ok := os.LookupEnv(key); ok {
		return envVar
	}
	return fallback
}
