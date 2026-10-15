package main

import (
	"bytes"
	"testing"

	"github.com/pion/rtp"
)

func TestForwardedRTPDoesNotReusePublisherTransportExtensions(t *testing.T) {
	packet := &rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: 96, SSRC: 123, SequenceNumber: 42, Timestamp: 9000, Marker: true},
		Payload: []byte{0x10, 0xA7, 0x02, 0xFF, 0x81},
	}
	// ID 3 may mean MID on the publisher and repaired-RID on the subscriber.
	if err := packet.SetExtension(3, []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := packet.SetExtension(4, []byte{0, 17}); err != nil {
		t.Fatal(err)
	}
	forwarded := cloneRTPPacket(packet)
	if forwarded.Extension || len(forwarded.Extensions) != 0 || forwarded.ExtensionProfile != 0 {
		t.Fatal("forwarded RTP retained publisher transport extension IDs")
	}
	if !bytes.Equal(forwarded.Payload, packet.Payload) || forwarded.SequenceNumber != packet.SequenceNumber || forwarded.Timestamp != packet.Timestamp || forwarded.Marker != packet.Marker {
		t.Fatal("rewriting transport metadata changed encoded media")
	}
	if !packet.Extension || string(packet.GetExtension(3)) != "1" {
		t.Fatal("source packet was mutated")
	}
	forwarded.Payload[0] ^= 1
	if forwarded.Payload[0] == packet.Payload[0] {
		t.Fatal("subscribers share mutable payload storage")
	}
}

func TestForwardedRTPPreservesPaddingAndPayload(t *testing.T) {
	packet := &rtp.Packet{Header: rtp.Header{Version: 2, Padding: true, PaddingSize: 16}, Payload: []byte{1, 2, 3}}
	forwarded := cloneRTPPacket(packet)
	wire, err := forwarded.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var received rtp.Packet
	if err := received.Unmarshal(wire); err != nil {
		t.Fatal(err)
	}
	if received.PaddingSize != 16 || !bytes.Equal(received.Payload, packet.Payload) {
		t.Fatal("padding changed media payload")
	}
}
