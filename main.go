package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	serverPort layers.TCPPort
	clientPort layers.TCPPort
)

// create a map of server payloads by Seq
// save only Server payloads responses
//
// when complete, serverResponse buffers should be application layer, HTTP response
func parsePacket(serverResponse map[uint32][]byte, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp, _ := layer.(*layers.TCP)

		// look for first ACK after 3-way handshake, set clientPort and serverPort
		if serverPort == 0 && !tcp.SYN && tcp.ACK {
			clientPort = tcp.SrcPort
			serverPort = tcp.DstPort // should be 80

			//  server response only
		} else if !tcp.SYN && tcp.ACK && tcp.SrcPort == serverPort {

			if _, found := serverResponse[tcp.Seq]; !found {
				serverResponse[tcp.Seq] = tcp.Payload
			}

		}
	}
}

func main() {

	var outFilename string
	inspect := flag.Bool("inspect", false, "boolean")
	flag.StringVar(&outFilename, "o", "reconstructed-file.jpg", "filename")

	flag.Parse()

	fo, err := os.Create("./" + outFilename)
	if err != nil {
		panic(err)
	}
	defer fo.Close()

	//                         Seq    http payload
	serverResponse := make(map[uint32][]byte)

	if handle, err := pcap.OpenOffline("./data/net.cap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		packetID := 0
		for packet := range packetSource.Packets() {
			if *inspect {
				fmt.Printf("Parsing Packet: %d\n", packetID)
				inspectPacket(packet)
				packetID++
			}
			parsePacket(serverResponse, packet)
		}

		// order serverResponse Seq numbers
		seqs := make([]uint32, 0, len(serverResponse))
		responseLength := 0
		for seq := range serverResponse {
			seqs = append(seqs, seq)
			responseLength += len(serverResponse[seq])
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

		// reconstruct response
		reconstructedResponse := make([]byte, 0, responseLength)
		for _, seq := range seqs {
			reconstructedResponse = append(reconstructedResponse, serverResponse[seq]...)
		}

		// strip out http headers
		httpHeaderSeparator := []byte("\r\n\r\n")
		httpBodyIndex := bytes.Index(reconstructedResponse, httpHeaderSeparator)
		if httpBodyIndex < 0 {
			panic(fmt.Sprintf("reconstructed response does not contain http response body separator: %v", httpHeaderSeparator))
		}

		reconstructedResponse = reconstructedResponse[httpBodyIndex+len(httpHeaderSeparator):]

		// write file
		fo.Write(reconstructedResponse)
	}

}
