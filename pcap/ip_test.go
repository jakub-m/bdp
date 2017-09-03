package pcap_test

import (
  "testing"
  "jakub-m/bdp/pcap"
)

func TestParseRegular(t *testing.T) {
  ip, err := pcap.IPv4FromString("1.0.2.255")
  if err != nil {
    t.Fatal(err)
  }
  if ip != pcap.IPv4([4]byte{1, 0, 2, 255}) {
    t.Fatal(ip)
  }
}

func TestParseOverflow(t *testing.T) {
  _, err := pcap.IPv4FromString("1.0.2.256")
  if err == nil {
    t.Fail()
  }
}

func TestParseNothing(t *testing.T) {
  _, err := pcap.IPv4FromString("")
  if err == nil {
    t.Fail()
  }
}

func TestTooMuchDigits(t *testing.T) {
  _, err := pcap.IPv4FromString("1.1.1.1.1")
  if err == nil {
    t.Fail()
  }
}

func TestParseIllegal(t *testing.T) {
  _, err := pcap.IPv4FromString("1.1.-1.1")
  if err == nil {
    t.Fail()
  }
}
