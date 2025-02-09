package swarm

import (
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	dockerclient "github.com/docker/docker/client"
	"golang.org/x/net/context"
)

type SwarmNode struct {
	Ip        string
	Hostname  string
	IsManager bool
	Ignore    bool
	DnsNames  []string
}

type Client interface {
	ListActiveNodes() ([]SwarmNode, error)
}

type swarmClient struct {
	api *dockerclient.Client
}

func NewClient() (Client, error) {
	cli, err := dockerclient.NewEnvClient()
	if err != nil {
		return nil, err
	}

	return swarmClient{api: cli}, nil
}

func (client swarmClient) ListActiveNodes() ([]SwarmNode, error) {
	var listOptions types.NodeListOptions
	apiNodes, err := client.api.NodeList(context.Background(), listOptions)
	if err != nil {
		return nil, err
	}

	var nodes []SwarmNode
	var ip string
	for _, node := range apiNodes {
		if node.Status.State == swarm.NodeStateReady {
			if publicIp, ok := node.Spec.Annotations.Labels["public-ip"]; ok {
				ip = publicIp
			} else if node.Status.Addr == "0.0.0.0" {
				ip = getIPFromAddr(node.ManagerStatus.Addr)
				if err != nil {
					return nil, err
				}
			} else {
				ip = node.Status.Addr
			}

			_, ignore := node.Spec.Annotations.Labels["swarmdns-ignore"]

			nodes = append(nodes,
				SwarmNode{
					Ip:        ip,
					Hostname:  getHostname(node),
					IsManager: node.ManagerStatus != nil,
					Ignore:    ignore,
					DnsNames:  getDnsNames(node),
				})
		}
	}

	return nodes, nil
}

func getHostname(node swarm.Node) string {
	hostname := node.Spec.Annotations.Labels["hostname"]
	if hostname == "" {
		hostname = node.Description.Hostname
	}
	return hostname
}

func getIPFromAddr(addr string) string {
	ipAndPort := strings.Split(addr, ":")
	return ipAndPort[0]
}

func getDnsNames(node swarm.Node) []string {
	var namesStr = node.Spec.Annotations.Labels["swarmdns-names"]

	if len(namesStr) <= 0 {
		return []string{}
	}

	var names = strings.Split(namesStr, ",")

	// Just to trim whitespaces
	for i, name := range names {
		names[i] = strings.Trim(name, " ")
	}

	return names
}
