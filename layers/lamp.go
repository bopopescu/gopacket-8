// Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
)

// LAMPTLVType is the type of each TLV value in a Marker packet.
type LAMPTLVType byte
type LAMPVersionType byte

const LAMPMarkerTlvLength uint8 = 0x10

const (
	LAMPVersion1 LAMPVersionType = 1
)

const (
	LAMPTLVTerminator      LAMPTLVType = 0
	LAMPTLVMarkerInfo      LAMPTLVType = 1
	LAMPTLVMarkerResponder LAMPTLVType = 2
)

type LAMPValue struct {
	TlvType LAMPTLVType
	Length  uint8
	Value   []byte
}

// Marker and Marker Response TLV.
type LAMPMarkerTlv struct {
	TlvType                LAMPTLVType
	Length                 uint8
	RequesterPort          uint16
	RequesterSystem        [6]uint8
	RequesterTransactionId uint32
	Pad                    uint16
}

type LAMPTerminatorTlv struct {
	TlvType LAMPTLVType
	Length  uint8
}

// 6.5.3.3
// format of data below is conforms to
// version 1
type LAMP struct {
	BaseLayer
	Version LAMPVersionType
	// tlv 0x01/0x2, len 0x10
	Marker LAMPMarkerTlv
	// tlv 0x00, len 0
	Terminator LAMPTerminatorTlv
	// Reserved 90 bytes
	Reserved [90]byte
}

// LayerType returns LayerTypeLAMP
func (l *LAMP) LayerType() gopacket.LayerType {
	return LayerTypeLAMP
}

// decodeLAMP decodes the Marker and Marker Responder PDU
func decodeLAMP(data []byte, p gopacket.PacketBuilder) error {
	lamp := &LAMP{BaseLayer: BaseLayer{Contents: data}}
	var vals []LAMPValue
	vData := data[1:]
	lamp.Version = LAMPVersionType(data[0])
	for len(vData) > 0 {
		t := LAMPTLVType(vData[0])
		val := LAMPValue{TlvType: t, Length: vData[1]}
		if val.Length > 0 {
			val.Value = vData[2:val.Length]
		}
		vals = append(vals, val)
		if val.TlvType == LAMPTLVTerminator {
			break
		}
		if len(vData) < int(val.Length) {
			return fmt.Errorf("Malformed LAMP Header")
		}
		vData = vData[val.Length:]
	}
	if len(vals) < 2 {
		return fmt.Errorf("Missing mandatory LAMP TLV", vals)
	}

	pktEnd := false
	for _, v := range vals {
		switch v.TlvType {
		case LAMPTLVTerminator:
			pktEnd = true
		case LAMPTLVMarkerInfo, LAMPTLVMarkerResponder:
			lamp.Marker = LAMPMarkerTlv{TlvType: v.TlvType,
				Length:        v.Length,
				RequesterPort: binary.BigEndian.Uint16(v.Value[0:2]),
				RequesterSystem: [6]uint8{uint8(v.Value[2]), uint8(v.Value[3]), uint8(v.Value[4]),
					uint8(v.Value[5]), uint8(v.Value[6]), uint8(v.Value[7])},
				RequesterTransactionId: binary.BigEndian.Uint32(v.Value[8:12]),
			}
		}
	}

	if lamp.Marker.TlvType == 0 ||
		!pktEnd {
		return fmt.Errorf("Missing mandatory LAMP TLV")
	}
	p.AddLayer(lamp)
	//fmt.Println("decodeLAMP exit")
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l *LAMP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

	bytes, err := b.PrependBytes(109)
	if err != nil {
		fmt.Println("Error in Serialize to for LAMP")
		return err
	}
	bytes[0] = byte(l.Version)
	bytes[1] = byte(l.Marker.TlvType)
	bytes[2] = byte(l.Marker.Length)
	binary.BigEndian.PutUint16(bytes[3:], l.Marker.RequesterPort)
	bytes[5] = byte(l.Marker.RequesterSystem[0])
	bytes[6] = byte(l.Marker.RequesterSystem[1])
	bytes[7] = byte(l.Marker.RequesterSystem[2])
	bytes[8] = byte(l.Marker.RequesterSystem[3])
	bytes[9] = byte(l.Marker.RequesterSystem[4])
	bytes[10] = byte(l.Marker.RequesterSystem[5])
	binary.BigEndian.PutUint32(bytes[11:], l.Marker.RequesterTransactionId)

	return nil
}

func (l *LAMP) CanDecode() gopacket.LayerClass {
	return LayerTypeLAMP
}

func (t LAMPTLVType) String() (s string) {
	switch t {
	case LAMPTLVTerminator:
		s = "TLV End"
	case LAMPTLVMarkerInfo:
		s = "Marker Info"
	case LAMPTLVMarkerResponder:
		s = "Marker Response Info"
	default:
		s = "Unknown"
	}
	return
}
