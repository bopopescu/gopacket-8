// Copyright 2012, Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/google/gopacket"
	"net"
	"testing"
)

// packet taken from cloud shark vxlan.pcap, ICMP ping request
// TODO get a packet whose VNI is not ZERO!!!
var testUDPPacketVXLAN = []byte{
	0x00, 0x16, 0x3e, 0x08, 0x71, 0xcf, 0x36, 0xdc, 0x85, 0x1e, 0xb3, 0x40, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x86, 0xd2, 0xc0, 0x40, 0x00, 0x40, 0x11, 0x51, 0x52, 0xc0, 0xa8, 0xcb, 0x01, 0xc0, 0xa8,
	0xca, 0x01, 0xb0, 0x5d, 0x12, 0xb5, 0x00, 0x72, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x30, 0x88, 0x01, 0x00, 0x02, 0x00, 0x16, 0x3e, 0x37, 0xf6, 0x04, 0x08, 0x00,
	0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x23, 0x4f, 0xc0, 0xa8, 0xcb, 0x03,
	0xc0, 0xa8, 0xcb, 0x05, 0x08, 0x00, 0xf6, 0xf2, 0x05, 0x0c, 0x00, 0x01, 0xfc, 0xe2, 0x97, 0x51,
	0x00, 0x00, 0x00, 0x00, 0xa6, 0xf8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
	0x34, 0x35, 0x36, 0x37,
}

func TestUDPPacketVXLAN(t *testing.T) {
	p := gopacket.NewPacket(testUDPPacketVXLAN, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4,
		LayerTypeUDP, LayerTypeVxlan, LayerTypeEthernet, LayerTypeIPv4,
		LayerTypeICMPv4, gopacket.LayerTypePayload}, t)

	vxlanL := p.Layer(LayerTypeVxlan)
	if vxlanL == nil {
		t.Fatal("Failed to get a pointer to VXLAN struct")
	}
	vxlan, _ := vxlanL.(*VXLAN)
	if vxlan.Flags != 0x08 {
		t.Fatal("Failed to decode Flags properly")
	}

	if vxlan.VNI[0] != 0x00 ||
		vxlan.VNI[1] != 0x00 ||
		vxlan.VNI[2] != 0x00 {
		t.Fatal("Failed to decode VNI properly")
	}

}

func TestUDPPacketVXLANGetInnerEthernetLayer(t *testing.T) {
	p := gopacket.NewPacket(testUDPPacketVXLAN, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	// show how to extract the inner ethernet header
	vxlan := p.Layer(LayerTypeVxlan)
	p2 := gopacket.NewPacket(vxlan.LayerPayload(), LinkTypeEthernet, gopacket.Default)
	ethernetL := p2.Layer(LayerTypeEthernet)
	ethernet, _ := ethernetL.(*Ethernet)
	if ethernet == nil {
		t.Error("Failed to find ethernet header")
	}
	dstmac := net.HardwareAddr{0x00, 0x30, 0x88, 0x01, 0x00, 0x02}
	srcmac := net.HardwareAddr{0x00, 0x16, 0x3e, 0x37, 0xf6, 0x04}
	if ethernet.DstMAC[0] != dstmac[0] &&
		ethernet.DstMAC[1] != dstmac[1] &&
		ethernet.DstMAC[2] != dstmac[2] &&
		ethernet.DstMAC[3] != dstmac[3] &&
		ethernet.DstMAC[4] != dstmac[4] &&
		ethernet.DstMAC[5] != dstmac[5] &&
		ethernet.SrcMAC[0] != srcmac[0] &&
		ethernet.SrcMAC[1] != srcmac[1] &&
		ethernet.SrcMAC[2] != srcmac[2] &&
		ethernet.SrcMAC[3] != srcmac[3] &&
		ethernet.SrcMAC[4] != srcmac[4] &&
		ethernet.SrcMAC[5] != srcmac[5] &&
		ethernet.EthernetType != 0x0800 {
		t.Error("Decoded packet incorrect values")
	}

}

func BenchmarkDecodeVxlan(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testUDPPacketVXLAN, LinkTypeEthernet, gopacket.NoCopy)
	}
}
func BenchmarkDecodeVxlanLayer(b *testing.B) {
	var vxlan VXLAN
	for i := 0; i < b.N; i++ {
		vxlan.DecodeFromBytes(testUDPPacketVXLAN[ /*eth*/ 14+ /*ipv4*/ 20+ /*udp*/ 8:], gopacket.NilDecodeFeedback)
	}
}
func TesVxlanDoesNotMalloc(t *testing.T) {
	var vxlan VXLAN
	if n := testing.AllocsPerRun(1000, func() {
		if err := vxlan.DecodeFromBytes(testUDPPacketVXLAN[ /*eth*/ 14+ /*ipv4*/ 20+ /*udp*/ 8:], gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Error(n, "mallocs decoding Vxlan")
	}
}
