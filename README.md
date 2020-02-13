<h1 align="center">PCapture the Flag 🏴‍☠️</h1 >

<p align="center">
  <strong>Parsing tcpdump pcap file to reconstruct an image file</strong>
</p>

## Quick Start

parses pcap file, headers and body of each layer, reconstructs the original http payload into `reconstructed-file.jpg`

```sh
go run *.go
```

### custom file name

```sh
go run *.go -o test1.jpg
```

## Inspect Packets

added this for assistance while learning the exercise

See [./inspectPacket.go](./inspectPacket.go)

```sh
go run *.go -inspect
```

## Parsing Packet Capture File

See [./main.go](./main.go)

- read pcap file
- parse each captured packet
  - parse Link Layer
  - parse Network Layer
  - parse Transport
      - parse Application Layer payload
  - reconstruct response (app layer receive from server)
- write reconstructed packet data to file

