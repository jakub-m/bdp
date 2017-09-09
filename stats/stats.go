package stats

import (
	"fmt"
	"jakub-m/bdp/packet"
	"jakub-m/bdp/pcap"
	"sort"
)

type key struct {
	source pcap.IPv4
	dest   pcap.IPv4
}

type byCountT struct {
	keys   []key
	counts map[key]int
}

func byCount(counts map[key]int) byCountT {
	keys := []key{}
	for k := range counts {
		keys = append(keys, k)
	}
	return byCountT{
		keys:   keys,
		counts: counts,
	}
}

func (a byCountT) Len() int {
	return len(a.counts)
}

func (a byCountT) Swap(i, k int) {
	a.keys[i], a.keys[k] = a.keys[k], a.keys[i]
}

func (a byCountT) Less(i, k int) bool {
	return a.counts[a.keys[i]] < a.counts[a.keys[k]]
}

func ProcessPackets(packets []*packet.Packet) {
	counts := make(map[key]int)
	for _, p := range packets {
		counts[key{p.IP.SourceIP(), p.IP.DestIP()}]++
	}

	sorted := byCount(counts)
	sort.Sort(sort.Reverse(sorted))

	for _, k := range sorted.keys {
		fmt.Printf("%s\t%s\t%d\n", k.source, k.dest, counts[k])
	}
}
