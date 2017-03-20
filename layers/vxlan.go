// Copyright 2014 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
This layer decodes Vxlan as described in RFC 7348.

Draft can be found at
https://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-04#page-6


0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

  Outer Ethernet Header:
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |             Outer Destination MAC Address                     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Outer Destination MAC Address | Outer Source MAC Address      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                Outer Source MAC Address                       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Optional Ethertype = C-Tag 802.1Q   | Outer.VLAN Tag Information    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Ethertype = 0x0800            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Outer IPv4 Header:
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |Version|  IHL  |Type of Service|          Total Length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Identification        |Flags|      Fragment Offset    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Time to Live |Protocl=17(UDP)|   Header Checksum       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Outer Source IPv4 Address               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                   Outer Destination IPv4 Address              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Outer UDP Header:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       Source Port = xxxx      |       Dest Port = VXLAN Port  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           UDP Length          |        UDP Checksum           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    VXLAN Header:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |R|R|R|R|I|R|R|R|            Reserved                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                VXLAN Network Identifier (VNI) |   Reserved    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     0

    Inner Ethernet Header:             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Inner Destination MAC Address                     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Inner Destination MAC Address | Inner Source MAC Address      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                Inner Source MAC Address                       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     Optional Ethertype = C-Tag [802.1Q]    | Inner.VLAN Tag Information    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     Payload:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Ethertype of Original Payload |                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
            |                                  Original Ethernet Payload    |
            |                                                               |
            | (Note that the original Ethernet Frame's FCS is not included) |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Frame Check Sequence:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   New FCS (Frame Check Sequence) for Outer Ethernet Frame     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 1 VXLAN Frame Format with IPv4 Outer Header


 VXLAN UDP ports:
   Some linux boxes 8472
   IANA - 4789

*/

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

// slice used to dynamically add other udp ports
// that are associated with VXLAN.
var VxlanUdpPorts []UDPPort = make([]UDPPort, 0)

func ExtendVxlanUdpPorts(udp UDPPort) {
	VxlanUdpPorts = append(VxlanUdpPorts, udp)
}

// created to ensure that the ethernet frame is not padded
type VxlanEthernet struct {
	Ethernet
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (eth *VxlanEthernet) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if len(eth.DstMAC) != 6 {
		return fmt.Errorf("invalid dst MAC: %v", eth.DstMAC)
	}
	if len(eth.SrcMAC) != 6 {
		return fmt.Errorf("invalid src MAC: %v", eth.SrcMAC)
	}
	payload := b.Bytes()
	bytes, err := b.PrependBytes(14)
	if err != nil {
		return err
	}
	copy(bytes, eth.DstMAC)
	copy(bytes[6:], eth.SrcMAC)
	if eth.Length != 0 || eth.EthernetType == EthernetTypeLLC {
		if opts.FixLengths {
			eth.Length = uint16(len(payload))
		}
		if eth.EthernetType != EthernetTypeLLC {
			return fmt.Errorf("ethernet type %v not compatible with length value %v", eth.EthernetType, eth.Length)
		} else if eth.Length > 0x0600 {
			return fmt.Errorf("invalid ethernet length %v", eth.Length)
		}
		binary.BigEndian.PutUint16(bytes[12:], eth.Length)
	} else {
		binary.BigEndian.PutUint16(bytes[12:], uint16(eth.EthernetType))
	}
	return nil
}

type VXLAN struct {
	BaseLayer
	Flags     byte
	Reserved1 [3]byte
	VNI       [3]byte
	Reserved2 byte
}

// VNI is a 24 bit value lets add to byte fields approprately
func (v *VXLAN) SetVNI(vni uint32) {
	v.VNI[2] = byte(vni >> 0 & 0xff)
	v.VNI[1] = byte(vni >> 8 & 0xff)
	v.VNI[0] = byte(vni >> 16 & 0xff)
}

// LayerType returns LayerTypeVxlan
func (v *VXLAN) LayerType() gopacket.LayerType {
	return LayerTypeVxlan
}

func (v *VXLAN) NextLayerType() gopacket.LayerType {
	return LayerTypeEthernet
}

func (v *VXLAN) CanDecode() gopacket.LayerClass {
	return LayerTypeVxlan
}

func (v *VXLAN) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	if len(data) < 8 {
		return fmt.Errorf("Vxlan: length of vxlan packet invalid", len(data))
	}

	v.Flags = data[0]
	if v.Flags != 0x08 {
		return fmt.Errorf("Vxlan: Flags set incorrectly got 0x%x expect 0x80", v.Flags)
	}
	v.SetVNI(binary.BigEndian.Uint32(data[4:8]) >> 8)
	v.Payload = data[8:]

	return nil
}

func decodeVxlan(data []byte, p gopacket.PacketBuilder) error {
	v := &VXLAN{BaseLayer: BaseLayer{Contents: data}}
	err := v.DecodeFromBytes(data, p)
	p.AddLayer(v)
	if err != nil {
		return err
	}
	return p.NextDecoder(v.NextLayerType())
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (v *VXLAN) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

	bytes, err := b.PrependBytes(8)
	if err != nil {
		fmt.Println("Error in Serialize to for VXLAN")
		return err
	}
	bytes[0] = byte(v.Flags)
	// bytes 1-3 Reserved
	bytes[4] = byte(v.VNI[0])
	bytes[5] = byte(v.VNI[1])
	bytes[6] = byte(v.VNI[2])
	// bytes 7 Reserved

	return nil
}
