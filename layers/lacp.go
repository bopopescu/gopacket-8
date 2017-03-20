// Copyright 2012 Google, Inc. All rights reserved.
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

const LACPActorTlvLength uint8 = 0x14
const LACPPartnerTlvLength uint8 = 0x14
const LACPCollectorTlvLength uint8 = 0x10

// LLDPTLVType is the type of each TLV value in a LinkLayerDiscovery packet.
type LACPTLVType byte
type LACPVersionType byte
type LACPSubTypeType byte

const (
	LACPVersion1 LACPVersionType = 1
	LACPVersion2 LACPVersionType = 2
)
const (
	LACPTLVTerminator                     LACPTLVType = 0
	LACPTLVActorInfo                      LACPTLVType = 1
	LACPTLVPartnerInfo                    LACPTLVType = 2
	LACPTLVCollectorInfo                  LACPTLVType = 3
	LACPTLVPortAlgorithm                  LACPTLVType = 4
	LACPTLVPortConversationIdDigest       LACPTLVType = 5
	LACPTLVPortConversationMask1          LACPTLVType = 6
	LACPTLVPortConversationMask2          LACPTLVType = 7
	LACPTLVPortConversationMask3          LACPTLVType = 8
	LACPTLVPortConversationMask4          LACPTLVType = 9
	LACPTLVPortConversationServiceMapping LACPTLVType = 10
)

// LACPValue is a TLV value inside a LACPPDU packet layer.
type LACPValue struct {
	TlvType LACPTLVType
	Length  uint8
	Value   []byte
}

type LACPSystem struct {
	SystemPriority uint16
	// MAC address component of the System Id
	SystemId [6]uint8
}

type LACPPortInfo struct {
	System  LACPSystem
	Key     uint16
	PortPri uint16
	Port    uint16
	State   uint8
}

type LACPInfoTlv struct {
	TlvType  LACPTLVType
	Length   uint8
	Info     LACPPortInfo
	Reserved [3]uint8
}

// 6.4.3.2
type LACPCollectorInfoTlv struct {
	TlvType  LACPTLVType // 0x03
	Length   uint8       // 0x10
	MaxDelay uint16
	Reserved [12]uint8
}

// 6.4.2.4 Version 2 TLV
// 6.4.2.4.1  Port Algorithm TLV 0x04
//
//
//  Algorithm         Value
//  Unspecified         0
//  C-VID               1
//  S-VID               2
//  I-SID               3
//  TE-SID              4
//  ECMP Flow Hash      5
//  Reserved            6-255
type LACPPortAlgorithmTlv struct {
	TlvType            LACPTLVType
	Length             uint8 // 6
	ActorPortAlgorithm uint32
}

// 6.4.2.4 Version 2 TLV
// 6.4.2.4.2 Port Conversation ID digest TLV 0x05
type LACPPortConversationIdDigestTlv struct {
	TlvType                         LACPTLVType
	Length                          uint8 // 0x14
	LinkNumberId                    uint16
	ActorConversationLinkListDigest [16]uint8
}

// 6.4.2.4 Version 2 TLV
// 6.4.2.4.3 Port Conversation Mask 1 TLV 0x06
type LACPPortConversationMask1Tlv struct {
	TlvType   LACPTLVType
	Length    uint8 // 131
	MaskState uint8
	Mask1     [128]uint8
}

// 6.4.2.4 Version 2 TLV
// 6.4.2.4.3 Port Conversation Mask 2 TLV 0x07
type LACPPortConversationMask2Tlv struct {
	TlvType    LACPTLVType
	MaskLength uint8 // 130
	Mask2      [128]uint8
}

// 6.4.2.4 Version 2 TLV
// 6.4.2.4.3 Port Conversation Mask 3 TLV 0x08
type LACPPortConversationMask3Tlv struct {
	TlvType    LACPTLVType
	MaskLength uint8 // 130
	Mask3      [128]uint8
}

// 6.4.2.4 Version 2 TLV
// 6.4.2.4.3 Port Conversation Mask 4 TLV 0x09
type LACPPortConversationMask4Tlv struct {
	TlvType    LACPTLVType
	MaskLength uint8 // 130
	Mask4      [128]uint8
}

// 6.4.2.4 Version 2 TLV
// 6.4.2.4.4 Port Conversation Service Mapping TLV 0x0A
type LACPPortConversationServiceMappingTlv struct {
	TlvType LACPTLVType
	Length  uint8 // 18
	Actor   [16]uint8
}

// 6.4.2.3
// format of data below is conforms to
// version 1 && 2, but version 2 allows
// for additional TLV's
type LACP struct {
	BaseLayer
	Version LACPVersionType
	// tlv 0x01, len 0x14
	Actor LACPInfoTlv
	// tlv 0x02, len 0x14
	Partner LACPInfoTlv
	// tlv 0x03, len 0x10
	Collector LACPCollectorInfoTlv
	// Version 2 TLV follow but not included in
	// this structure as they are optional and
	// variable
	Values []LACPValue
}

// LayerType returns LayerTypeLACP
func (l *LACP) LayerType() gopacket.LayerType {
	return LayerTypeLACP
}

// TOOD Function only decodes Version 1
func decodeLACP(data []byte, p gopacket.PacketBuilder) error {
	lacp := &LACP{BaseLayer: BaseLayer{Contents: data}}
	var vals []LACPValue
	vData := data[1:]
	lacp.Version = LACPVersionType(data[0])
	for len(vData) > 0 {
		t := LACPTLVType(vData[0])
		val := LACPValue{TlvType: t, Length: vData[1]}
		if val.Length > 0 {
			val.Value = vData[2:val.Length]
		}
		vals = append(vals, val)
		if val.TlvType == LACPTLVTerminator {
			break
		}
		if len(vData) < int(val.Length) {
			return fmt.Errorf("Malformed LACP Header")
		}
		vData = vData[val.Length:]
	}
	if len(vals) < 3 {
		return fmt.Errorf("Missing mandatory LACP TLV")
	}

	pktEnd := false
	for _, v := range vals {
		switch v.TlvType {
		case LACPTLVTerminator:
			pktEnd = true
		case LACPTLVActorInfo:
			lacp.Actor = LACPInfoTlv{TlvType: v.TlvType,
				Length: v.Length,
				Info: LACPPortInfo{System: LACPSystem{SystemPriority: binary.BigEndian.Uint16(v.Value[0:2]),
					SystemId: [6]uint8{uint8(v.Value[2]), uint8(v.Value[3]), uint8(v.Value[4]),
						uint8(v.Value[5]), uint8(v.Value[6]), uint8(v.Value[7])},
				},
					Key:     binary.BigEndian.Uint16(v.Value[8:10]),
					PortPri: binary.BigEndian.Uint16(v.Value[10:12]),
					Port:    binary.BigEndian.Uint16(v.Value[12:14]),
					State:   v.Value[14],
				},
			}
		case LACPTLVPartnerInfo:
			lacp.Partner = LACPInfoTlv{TlvType: v.TlvType,
				Length: v.Length,
				Info: LACPPortInfo{System: LACPSystem{SystemPriority: binary.BigEndian.Uint16(v.Value[0:2]),
					SystemId: [6]uint8{uint8(v.Value[2]), uint8(v.Value[3]), uint8(v.Value[4]),
						uint8(v.Value[5]), uint8(v.Value[6]), uint8(v.Value[7])},
				},
					Key:     binary.BigEndian.Uint16(v.Value[8:10]),
					PortPri: binary.BigEndian.Uint16(v.Value[10:12]),
					Port:    binary.BigEndian.Uint16(v.Value[12:14]),
					State:   v.Value[14],
				},
			}
		case LACPTLVCollectorInfo:
			lacp.Collector = LACPCollectorInfoTlv{TlvType: v.TlvType,
				Length:   v.Length,
				MaxDelay: binary.BigEndian.Uint16(v.Value[0:2]),
			}
		case LACPTLVPortAlgorithm:
			if lacp.Version == LACPVersion1 {
				return fmt.Errorf("Unsupported TLV[%d] in Version 1", v.TlvType)
			}
		case LACPTLVPortConversationIdDigest:
			if lacp.Version == LACPVersion1 {
				return fmt.Errorf("Unsupported TLV[%d] in Version 1", v.TlvType)
			}
		case LACPTLVPortConversationMask1:
			if lacp.Version == LACPVersion1 {
				return fmt.Errorf("Unsupported TLV[%d] in Version 1", v.TlvType)
			}
		case LACPTLVPortConversationMask2:
			if lacp.Version == LACPVersion1 {
				return fmt.Errorf("Unsupported TLV[%d] in Version 1", v.TlvType)
			}
		case LACPTLVPortConversationMask3:
			if lacp.Version == LACPVersion1 {
				return fmt.Errorf("Unsupported TLV[%d] in Version 1", v.TlvType)
			}
		case LACPTLVPortConversationMask4:
			if lacp.Version == LACPVersion1 {
				return fmt.Errorf("Unsupported TLV[%d] in Version 1", v.TlvType)
			}
		case LACPTLVPortConversationServiceMapping:
			if lacp.Version == LACPVersion1 {
				return fmt.Errorf("Unsupported TLV[%d] in Version 1", v.TlvType)
			}
		default:
			lacp.Values = append(lacp.Values, v)
		}
	}

	if lacp.Actor.TlvType == 0 || lacp.Partner.TlvType == 0 || lacp.Collector.TlvType == 0 ||
		!pktEnd {
		return fmt.Errorf("Missing mandatory LACP TLV")
	}
	p.AddLayer(lacp)
	//fmt.Println("decodeLACP exit")
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l *LACP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// TODO only supports Version 1
	bytes, err := b.PrependBytes(109)
	if err != nil {
		fmt.Println("Error in Serialize to for LACP")
		return err
	}
	bytes[0] = byte(l.Version)
	bytes[1] = byte(l.Actor.TlvType)
	bytes[2] = byte(l.Actor.Length)
	binary.BigEndian.PutUint16(bytes[3:], l.Actor.Info.System.SystemPriority)
	bytes[5] = byte(l.Actor.Info.System.SystemId[0])
	bytes[6] = byte(l.Actor.Info.System.SystemId[1])
	bytes[7] = byte(l.Actor.Info.System.SystemId[2])
	bytes[8] = byte(l.Actor.Info.System.SystemId[3])
	bytes[9] = byte(l.Actor.Info.System.SystemId[4])
	bytes[10] = byte(l.Actor.Info.System.SystemId[5])
	binary.BigEndian.PutUint16(bytes[11:], l.Actor.Info.Key)
	binary.BigEndian.PutUint16(bytes[13:], l.Actor.Info.PortPri)
	binary.BigEndian.PutUint16(bytes[15:], l.Actor.Info.Port)
	bytes[17] = byte(l.Actor.Info.State)
	// next 3 bytes reserved
	bytes[21] = byte(l.Partner.TlvType)
	bytes[22] = byte(l.Partner.Length)
	binary.BigEndian.PutUint16(bytes[23:], l.Partner.Info.System.SystemPriority)
	bytes[25] = byte(l.Partner.Info.System.SystemId[0])
	bytes[26] = byte(l.Partner.Info.System.SystemId[1])
	bytes[27] = byte(l.Partner.Info.System.SystemId[2])
	bytes[28] = byte(l.Partner.Info.System.SystemId[3])
	bytes[29] = byte(l.Partner.Info.System.SystemId[4])
	bytes[30] = byte(l.Partner.Info.System.SystemId[5])
	binary.BigEndian.PutUint16(bytes[31:], l.Partner.Info.Key)
	binary.BigEndian.PutUint16(bytes[33:], l.Partner.Info.PortPri)
	binary.BigEndian.PutUint16(bytes[35:], l.Partner.Info.Port)
	bytes[37] = byte(l.Partner.Info.State)
	// next 3 bytes reserved
	bytes[41] = byte(l.Collector.TlvType)
	bytes[42] = byte(l.Collector.Length)
	binary.BigEndian.PutUint16(bytes[43:], l.Collector.MaxDelay)

	return nil
}

func (l *LACP) CanDecode() gopacket.LayerClass {
	return LayerTypeLACP
}

func (t LACPTLVType) String() (s string) {
	switch t {
	case LACPTLVTerminator:
		s = "TLV Terminator"
	case LACPTLVActorInfo:
		s = "Actor Info"
	case LACPTLVPartnerInfo:
		s = "Partner Info"
	case LACPTLVCollectorInfo:
		s = "Collector Info"
	case LACPTLVPortAlgorithm:
		s = "Port Algorithm"
	case LACPTLVPortConversationIdDigest:
		s = "Port Conversation Id Digest"
	case LACPTLVPortConversationMask1:
		s = "Port Conversation Mask 1"
	case LACPTLVPortConversationMask2:
		s = "Port Conversation Mask 2"
	case LACPTLVPortConversationMask3:
		s = "Port Conversation Mask 3"
	case LACPTLVPortConversationMask4:
		s = "Port Conversation Mask 4"
	case LACPTLVPortConversationServiceMapping:
		s = "Port Coversation Service Mapping"
	default:
		s = "Unknown"
	}
	return
}
