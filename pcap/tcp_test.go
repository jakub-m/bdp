package pcap_test

import (
	"jakub-m/bdp/pcap"
	"math"
	"testing"
)

func TestSeqNum_Relative_ZeroZero(t *testing.T) {
	r := pcap.SeqNum(0)
	x := pcap.SeqNum(0)
	assertEqual(t, x.RelativeTo(r), pcap.SeqNum(0))
}

func TestSeqNum_Relative_ZeroSome(t *testing.T) {
	r := pcap.SeqNum(0)
	x := pcap.SeqNum(1)
	assertEqual(t, x.RelativeTo(r), pcap.SeqNum(1))
}

func TestSeqNum_Relative_SomeZero(t *testing.T) {
	r := pcap.SeqNum(1)
	x := pcap.SeqNum(0)
	assertEqual(t, x.RelativeTo(r), pcap.SeqNum(math.MaxUint32))
}

func assertEqual(t *testing.T, actual interface{}, expected interface{}) {
	if expected == actual {
		return
	}
	t.Fatalf("%v != %v", actual, expected)
}
