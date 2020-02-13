package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// for inspectPacket
func fmtFlags(tcp *layers.TCP) string {
	var str string

	if tcp.SYN && tcp.ACK {
		str = "SYN ACK"
	} else if tcp.SYN {
		str = "SYN    "
	} else if tcp.ACK {
		str = "    ACK"
	}
	if tcp.RST {
		str += " RST"
	}
	if tcp.PSH {
		str += " PSH"
	}
	if tcp.FIN {
		str += " FIN"
	}
	if tcp.URG {
		str += " URG"
	}
	if tcp.ECE {
		str += " ECE"
	}
	if tcp.CWR {
		str += " CWR"
	}
	if tcp.NS {
		str += " NS"
	}
	return str
}

// print for analysis
// https://godoc.org/github.com/google/gopacket#Packet
func inspectPacket(packet gopacket.Packet) {
	// fmt.Printf("Parsing Packet %s", packet.String())

	var networkLayer *layers.IPv4
	var _ bool

	for _, layer := range packet.Layers() {
		switch layer.LayerType() {

		case layers.LayerTypeEthernet: // https://godoc.org/github.com/google/gopacket/layers#Ethernet
			eth, _ := layer.(*layers.Ethernet)
			fmt.Printf("Ethernet Layer:\n\tsrc mac:%d\n\tdst mac:%d\n\tlength:%d\n", eth.SrcMAC, eth.DstMAC, eth.Length)

		case layers.LayerTypeIPv4:
			networkLayer, _ = layer.(*layers.IPv4)

		case layers.LayerTypeTCP:
			tcp, _ := layer.(*layers.TCP)
			tcp.SetNetworkLayerForChecksum(networkLayer)
			tcpChecksum, err := tcp.ComputeChecksum()
			if err != nil {
				fmt.Printf("TCP Checksum err%+v\n", err)
			}
			fmt.Printf("TCP Layer:\n\tsrc port:%d\tdst port:%d\n\tSeq:%d\tAck:%d\n\tFlags:%s\nChecksum:\n%+v\nComputedChecksum:\n%+v\n\n", tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, fmtFlags(tcp), tcp.Checksum, tcpChecksum)

		}
	}

}
