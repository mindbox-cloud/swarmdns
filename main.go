package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/djmaze/swarmdns/swarm"
	"github.com/miekg/dns"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

const NodeRefreshInterval = 60
const TTL = NodeRefreshInterval

var logger *log.Logger
var client swarm.Client
var logflag bool
var rateLimit int64
var nodes []swarm.SwarmNode
var nameToNodeMap map[string][]swarm.SwarmNode
var mutex = &sync.Mutex{}
var swarmDomains arrayFlags
var returnWorkers bool

func main() {
	var err error
	var handler dns.HandlerFunc

	flag.Var(&swarmDomains, "domain", "[required] Domain to resolve addresses for (can be specified multiple times)")
	flag.BoolVar(&logflag, "log", false, "Log requests to stdout")
	flag.Int64Var(&rateLimit, "rate-limit", 0, "Number of simultaneous requests being worked on")
	flag.BoolVar(&returnWorkers, "return-workers", false, "Return A records for workers")
	flag.Parse()

	if len(swarmDomains) == 0 {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "No domains given. Aborting.")
		os.Exit(1)
	}

	logger = log.New(os.Stderr, "", 0)

	logger.Printf("Using domains: %v", swarmDomains)

	if rateLimit > 0 {
		logger.Printf("Limiting the number of simultaneous requests to %d", rateLimit)
	}

	client, err = swarm.NewClient()
	if err != nil {
		panic(err)
	}

	refreshNodes()

	// Get IPs on every interval
	ticker := time.NewTicker(time.Second * NodeRefreshInterval)
	go func() {
		for range ticker.C {
			refreshNodes()
		}
	}()

	if rateLimit > 0 {
		limit := make(chan struct{}, rateLimit)
		handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			limit <- struct{}{}
			defer func() { <-limit }()
			handleRequest(w, r)
		})
	} else {
		handler = dns.HandlerFunc(handleRequest)
	}

	go func() {
		srv := &dns.Server{Addr: ":53", Net: "udp", Handler: handler}
		err := srv.ListenAndServe()
		if err != nil {
			logger.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case s := <-sig:
			logger.Fatalf("Signal (%d) received, stopping\n", s)
			ticker.Stop()
		}
	}
}

func matchingDomain(domain string) *string {
	normalizedDomain := strings.ToLower(domain)

	for _, name := range swarmDomains {
		if (normalizedDomain == name+".") || strings.HasSuffix(normalizedDomain, "."+name+".") {
			return &name
		}
	}
	return nil
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	domain := r.Question[0].Name
	swarmDomain := matchingDomain(domain)

	if swarmDomain != nil && r.Question[0].Qtype == 1 { // Only answer questions for A records on supported domains
		if logflag {
			ip, _, _ := net.SplitHostPort(w.RemoteAddr().String())
			logger.Printf("Request: %15s %s", ip, domain)
		}

		m.Answer = answerForNodes(domain)
	} else {
		m.Answer = []dns.RR{}
	}

	w.WriteMsg(m)
}

func replaceLast(s, search, replace string) string {
	i := strings.LastIndex(s, search)
	if i == -1 {
		return s
	}
	return s[:i] + replace + s[i+len(search):]
}

func answerForNodes(domain string) []dns.RR {
	mutex.Lock()
	var rrs []dns.RR
	var nodes = nodes

	var swarmDomain = *matchingDomain(domain) + "."
	var normDomain = strings.ToLower(domain)

	if swarmDomain != normDomain {
		var subDomain = replaceLast(normDomain, "."+swarmDomain, "")
		if len(nameToNodeMap[subDomain]) > 0 {
			nodes = nameToNodeMap[subDomain]
		}
	}

	for _, node := range nodes {
		if node.IsManager || returnWorkers {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(TTL)}
			rr.A = net.ParseIP(node.Ip)
			rrs = append(rrs, rr)
		}
	}
	mutex.Unlock()

	return shuffleRRs(rrs)
}

func shuffleRRs(src []dns.RR) []dns.RR {
	dest := make([]dns.RR, len(src))
	perm := rand.Perm(len(src))
	for i, v := range perm {
		dest[v] = src[i]
	}
	return dest
}

func refreshNodes() {
	var err error

	mutex.Lock()
	nodes, err = client.ListActiveNodes()
	mapNodesToNames(nodes)
	logger.Printf("Refreshed nodes: %v\n", nodes)
	mutex.Unlock()
	if err != nil {
		panic(err)
	}
}

func mapNodesToNames(nodes []swarm.SwarmNode) {
	var newMap = make(map[string][]swarm.SwarmNode)

	for _, node := range nodes {
		if len(node.DnsNames) <= 0 {
			continue
		}

		for _, name := range node.DnsNames {
			newMap[name] = append(newMap[name], node)

			logger.Printf("Mapped: [%v] to [%v]\n", node.Hostname, name)
		}
	}

	nameToNodeMap = newMap
}
