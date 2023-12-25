package awsclient

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2type "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// These interfaces are used for: Test function initilize an AWSClients using Mock client which implements these APIs.
type AWSAutoScalingAPI interface {
	DescribeAutoScalingGroups(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
}

type AWSEC2API interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

type AWSClient struct {
	EC2Client         AWSEC2API
	AutoScalingClient AWSAutoScalingAPI
	// Add more AWS service clients as needed
}

type InstanceAddress struct {
	InstanceID string
	IPAddress  string
	MacAdress  string
}

var DefaultAWSRegion = "ap-southeast-1"

func NewAWSClient(awsprofile *string) (*AWSClient, error) {
	var cfg aws.Config
	var err error
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = DefaultAWSRegion
	}
	if awsprofile != nil || *awsprofile == "" {
		cfg, err = config.LoadDefaultConfig(
			context.TODO(),
			config.WithSharedConfigProfile(*awsprofile),
			config.WithRegion(region),

			config.WithSharedCredentialsFiles([]string{"/home/ubuntu/.aws/credentials"}),
		)
		if err != nil {
			return nil, err
		}
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
		if err != nil {
			return nil, err
		}
	}
	return &AWSClient{
		EC2Client:         ec2.NewFromConfig(cfg),
		AutoScalingClient: autoscaling.NewFromConfig(cfg),
	}, nil
}

func (c *AWSClient) GetInstanceIDs(ctx context.Context, autoscalingName string) ([]string, error) {
	instanceIDs := []string{}
	scalingGroups, err := c.AutoScalingClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{autoscalingName},
	})
	if err != nil {
		return []string{}, err
	}
	for _, group := range scalingGroups.AutoScalingGroups {
		for _, instance := range group.Instances {
			instanceIDs = append(instanceIDs, *instance.InstanceId)
		}
	}

	return instanceIDs, nil
}

func (c *AWSClient) GetPrivateAddress(ctx context.Context, instanceIDs []string, tags []ec2type.Tag) ([]InstanceAddress, error) {

	var filters []ec2type.Filter

	for _, tag := range tags {
		filters = append(filters, ec2type.Filter{
			Name:   stringPtr(fmt.Sprintf("tag:%s", *tag.Key)),
			Values: []string{*tag.Value},
		})
	}

	describeInstancesOutput, err := c.EC2Client.DescribeInstances(
		ctx, &ec2.DescribeInstancesInput{
			Filters:     filters,
			InstanceIds: instanceIDs,
		},
	)
	if err != nil {
		return []InstanceAddress{}, err
	}

	instanceAddresses := []InstanceAddress{}
	for _, reservation := range describeInstancesOutput.Reservations {
		for _, instance := range reservation.Instances {
			for _, iface := range instance.NetworkInterfaces {
				if *iface.Attachment.DeviceIndex == 0 {
					instanceAddresses = append(instanceAddresses, InstanceAddress{
						InstanceID: *instance.InstanceId,
						IPAddress:  *iface.PrivateIpAddress,
						MacAdress:  *iface.MacAddress,
					})
				}
			}
		}
	}

	return instanceAddresses, nil
}

func stringPtr(s string) *string { return &s }
