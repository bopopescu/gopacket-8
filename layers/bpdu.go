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
	"net"
)

const RSTPProtocolIdentifier uint16 = 0x00

const STPProtocolVersion uint8 = 0x00
const TCNProtocolVersion uint8 = 0x01
const RSTPProtocolVersion uint8 = 0x02
const PVSTProtocolVersion uint8 = 0x02

const BPDUTypeSTP StpBpduType = 0x00
const BPDUTypeRSTP StpBpduType = 0x02
const BPDUTypePVST StpBpduType = 0x02
const BPDUTypeTopoChange StpBpduType = 0x80

const STPProtocolLength int = 35
const RSTPProtocolLength int = 36
const PVSTProtocolLength int = 42
const BPDUTopologyLength int = 4

var BpduDMAC net.HardwareAddr = net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}
var BpduPVSTDMAC net.HardwareAddr = net.HardwareAddr{0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD}

const (
	RoleMasterPort          byte = 0
	RoleAlternateBackupPort byte = 1
	RoleRootPort            byte = 2
	RoleDesignatedPort      byte = 3
)

type StpBpduType uint8
type StpFlags byte

const (
	// 9.3.1/3 bit encodings for octet 5
	TopoChangeFlag    StpFlags = 0x01
	ProposalFlag      StpFlags = 0x02
	PortRoleFlag      StpFlags = 0x06
	LearningFlag      StpFlags = 0x10
	ForwardingFlag    StpFlags = 0x20
	AgreementFlag     StpFlags = 0x40
	TopoChangeAckFlag StpFlags = 0x80
)

type STPOriginatingVlanTlv struct {
	Type     uint16
	Length   uint16
	OrigVlan uint16
}

// 802.1d section 9
type STP struct {
	BaseLayer
	ProtocolId        uint16
	ProtocolVersionId byte
	BPDUType          StpBpduType
	Flags             StpFlags
	RootId            [8]byte
	RootPathCost      uint32
	BridgeId          [8]byte
	PortId            uint16
	MsgAge            uint16
	MaxAge            uint16
	HelloTime         uint16
	FwdDelay          uint16
}

// 802.1d section 9.3
type RSTP struct {
	BaseLayer
	ProtocolId        uint16
	ProtocolVersionId byte
	BPDUType          StpBpduType
	Flags             StpFlags
	RootId            [8]byte
	RootPathCost      uint32
	BridgeId          [8]byte
	PortId            uint16
	MsgAge            uint16
	MaxAge            uint16
	HelloTime         uint16
	FwdDelay          uint16
	Version1Length    uint8
}

// Cisco proprietary
type PVST struct {
	BaseLayer
	ProtocolId        uint16
	ProtocolVersionId byte
	BPDUType          StpBpduType
	Flags             StpFlags
	RootId            [8]byte
	RootPathCost      uint32
	BridgeId          [8]byte
	PortId            uint16
	MsgAge            uint16
	MaxAge            uint16
	HelloTime         uint16
	FwdDelay          uint16
	Version1Length    uint8
	OriginatingVlan   STPOriginatingVlanTlv
}

// 802.1d 9.3.2
type BPDUTopology struct {
	BaseLayer
	ProtocolId        uint16
	ProtocolVersionId byte
	BPDUType          StpBpduType
}

// LayerType returns LayerTypeSTP
func (l *STP) LayerType() gopacket.LayerType {
	return LayerTypeBPDU
}

func (l *RSTP) LayerType() gopacket.LayerType {
	return LayerTypeBPDU
}

func (l *PVST) LayerType() gopacket.LayerType {
	return LayerTypePVST
}

func (l *BPDUTopology) LayerType() gopacket.LayerType {
	return LayerTypeBPDU
}

// Function will decode the various BPDU types
func decodeBPDU(data []byte, p gopacket.PacketBuilder) error {

	protocolversion := data[2]
	bpdutype := StpBpduType(data[3])

	// STP is 35 bytes
	// RSTP is 36 bytes
	if protocolversion == uint8(bpdutype) {
		if bpdutype == BPDUTypeSTP {
			pdu := &STP{BaseLayer: BaseLayer{Contents: data}}
			pdu.ProtocolId = binary.BigEndian.Uint16(data[0:2])
			pdu.ProtocolVersionId = data[2]
			pdu.BPDUType = StpBpduType(data[3])
			pdu.Flags = StpFlags(data[4])
			pdu.RootId = [8]uint8{data[5], data[6], data[7], data[8],
				data[9], data[10], data[11], data[12]}
			pdu.RootPathCost = binary.BigEndian.Uint32(data[13:17])
			pdu.BridgeId = [8]uint8{data[17], data[18], data[19], data[20],
				data[21], data[22], data[23], data[24]}
			pdu.PortId = binary.BigEndian.Uint16(data[25:27])
			pdu.MsgAge = binary.BigEndian.Uint16(data[27:29])
			pdu.MaxAge = binary.BigEndian.Uint16(data[29:31])
			pdu.HelloTime = binary.BigEndian.Uint16(data[31:33])
			pdu.FwdDelay = binary.BigEndian.Uint16(data[33:35])

			p.AddLayer(pdu)

		} else if bpdutype == BPDUTypeRSTP {
			pdu := &RSTP{BaseLayer: BaseLayer{Contents: data}}
			pdu.ProtocolId = binary.BigEndian.Uint16(data[0:2])
			pdu.ProtocolVersionId = data[2]
			pdu.BPDUType = StpBpduType(data[3])
			pdu.Flags = StpFlags(data[4])
			pdu.RootId = [8]uint8{data[5], data[6], data[7], data[8],
				data[9], data[10], data[11], data[12]}
			pdu.RootPathCost = binary.BigEndian.Uint32(data[13:17])
			pdu.BridgeId = [8]uint8{data[17], data[18], data[19], data[20],
				data[21], data[22], data[23], data[24]}
			pdu.PortId = binary.BigEndian.Uint16(data[25:27])
			pdu.MsgAge = binary.BigEndian.Uint16(data[27:29])
			pdu.MaxAge = binary.BigEndian.Uint16(data[29:31])
			pdu.HelloTime = binary.BigEndian.Uint16(data[31:33])
			pdu.FwdDelay = binary.BigEndian.Uint16(data[33:35])
			pdu.Version1Length = data[35]

			p.AddLayer(pdu)
		}
	} else if bpdutype == BPDUTypeTopoChange {
		pdu := &BPDUTopology{BaseLayer: BaseLayer{Contents: data}}
		pdu.ProtocolId = binary.BigEndian.Uint16(data[0:2])
		pdu.ProtocolVersionId = data[2]
		pdu.BPDUType = StpBpduType(data[3])

		p.AddLayer(pdu)
	} else {
		return fmt.Errorf("Error unknown BPDU type")
	}

	//fmt.Println("decodePBDU exit")
	return nil
}

// Function will decode the various BPDU types
func decodePVST(data []byte, p gopacket.PacketBuilder) error {

	protocolversion := data[2]
	bpdutype := StpBpduType(data[3])

	if protocolversion == uint8(bpdutype) {
		if bpdutype == BPDUTypeRSTP ||
			bpdutype == BPDUTypeSTP {
			pdu := &PVST{BaseLayer: BaseLayer{Contents: data}}
			pdu.ProtocolId = binary.BigEndian.Uint16(data[0:2])
			pdu.ProtocolVersionId = data[2]
			pdu.BPDUType = StpBpduType(data[3])
			pdu.Flags = StpFlags(data[4])
			pdu.RootId = [8]uint8{data[5], data[6], data[7], data[8],
				data[9], data[10], data[11], data[12]}
			pdu.RootPathCost = binary.BigEndian.Uint32(data[13:17])
			pdu.BridgeId = [8]uint8{data[17], data[18], data[19], data[20],
				data[21], data[22], data[23], data[24]}
			pdu.PortId = binary.BigEndian.Uint16(data[25:27])
			pdu.MsgAge = binary.BigEndian.Uint16(data[27:29])
			pdu.MaxAge = binary.BigEndian.Uint16(data[29:31])
			pdu.HelloTime = binary.BigEndian.Uint16(data[31:33])
			pdu.FwdDelay = binary.BigEndian.Uint16(data[33:35])
			pdu.Version1Length = data[35]
			pdu.OriginatingVlan.Type = binary.BigEndian.Uint16(data[36:38])
			pdu.OriginatingVlan.Length = binary.BigEndian.Uint16(data[38:40])
			pdu.OriginatingVlan.OrigVlan = binary.BigEndian.Uint16(data[40:42])

			p.AddLayer(pdu)
		} else {
			return fmt.Errorf("Error unknown PVST BPDU type")
		}
	} else {
		return fmt.Errorf("Error unknown PVST version/bpdutype")
	}

	//fmt.Println("decodePVST exit")
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l *STP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// TODO only supports Version 1
	bytes, err := b.PrependBytes(STPProtocolLength)
	if err != nil {
		fmt.Println("Error in Serialize to for STP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], l.ProtocolId)
	bytes[2] = byte(l.ProtocolVersionId)
	bytes[3] = byte(l.BPDUType)
	bytes[4] = byte(l.Flags)
	bytes[5] = byte(l.RootId[0])
	bytes[6] = byte(l.RootId[1])
	bytes[7] = byte(l.RootId[2])
	bytes[8] = byte(l.RootId[3])
	bytes[9] = byte(l.RootId[4])
	bytes[10] = byte(l.RootId[5])
	bytes[11] = byte(l.RootId[6])
	bytes[12] = byte(l.RootId[7])
	binary.BigEndian.PutUint32(bytes[13:], l.RootPathCost)
	bytes[17] = byte(l.BridgeId[0])
	bytes[18] = byte(l.BridgeId[1])
	bytes[19] = byte(l.BridgeId[2])
	bytes[20] = byte(l.BridgeId[3])
	bytes[21] = byte(l.BridgeId[4])
	bytes[22] = byte(l.BridgeId[5])
	bytes[23] = byte(l.BridgeId[6])
	bytes[24] = byte(l.BridgeId[7])
	binary.BigEndian.PutUint16(bytes[25:], l.PortId)
	binary.BigEndian.PutUint16(bytes[27:], l.MsgAge)
	binary.BigEndian.PutUint16(bytes[29:], l.MaxAge)
	binary.BigEndian.PutUint16(bytes[31:], l.HelloTime)
	binary.BigEndian.PutUint16(bytes[33:], l.FwdDelay)

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l *RSTP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// TODO only supports Version 1
	bytes, err := b.PrependBytes(RSTPProtocolLength)
	if err != nil {
		fmt.Println("Error in Serialize to for RSTP")
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:], l.ProtocolId)
	bytes[2] = byte(l.ProtocolVersionId)
	bytes[3] = byte(l.BPDUType)
	bytes[4] = byte(l.Flags)
	bytes[5] = byte(l.RootId[0])
	bytes[6] = byte(l.RootId[1])
	bytes[7] = byte(l.RootId[2])
	bytes[8] = byte(l.RootId[3])
	bytes[9] = byte(l.RootId[4])
	bytes[10] = byte(l.RootId[5])
	bytes[11] = byte(l.RootId[6])
	bytes[12] = byte(l.RootId[7])
	binary.BigEndian.PutUint32(bytes[13:], l.RootPathCost)
	bytes[17] = byte(l.BridgeId[0])
	bytes[18] = byte(l.BridgeId[1])
	bytes[19] = byte(l.BridgeId[2])
	bytes[20] = byte(l.BridgeId[3])
	bytes[21] = byte(l.BridgeId[4])
	bytes[22] = byte(l.BridgeId[5])
	bytes[23] = byte(l.BridgeId[6])
	bytes[24] = byte(l.BridgeId[7])
	binary.BigEndian.PutUint16(bytes[25:], l.PortId)
	binary.BigEndian.PutUint16(bytes[27:], l.MsgAge)
	binary.BigEndian.PutUint16(bytes[29:], l.MaxAge)
	binary.BigEndian.PutUint16(bytes[31:], l.HelloTime)
	binary.BigEndian.PutUint16(bytes[33:], l.FwdDelay)
	bytes[35] = l.Version1Length
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l *PVST) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// TODO only supports Version 1
	bytes, err := b.PrependBytes(PVSTProtocolLength)
	if err != nil {
		fmt.Println("Error in Serialize to for PVST")
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:], l.ProtocolId)
	bytes[2] = byte(l.ProtocolVersionId)
	bytes[3] = byte(l.BPDUType)
	bytes[4] = byte(l.Flags)
	bytes[5] = byte(l.RootId[0])
	bytes[6] = byte(l.RootId[1])
	bytes[7] = byte(l.RootId[2])
	bytes[8] = byte(l.RootId[3])
	bytes[9] = byte(l.RootId[4])
	bytes[10] = byte(l.RootId[5])
	bytes[11] = byte(l.RootId[6])
	bytes[12] = byte(l.RootId[7])
	binary.BigEndian.PutUint32(bytes[13:], l.RootPathCost)
	bytes[17] = byte(l.BridgeId[0])
	bytes[18] = byte(l.BridgeId[1])
	bytes[19] = byte(l.BridgeId[2])
	bytes[20] = byte(l.BridgeId[3])
	bytes[21] = byte(l.BridgeId[4])
	bytes[22] = byte(l.BridgeId[5])
	bytes[23] = byte(l.BridgeId[6])
	bytes[24] = byte(l.BridgeId[7])
	binary.BigEndian.PutUint16(bytes[25:], l.PortId)
	binary.BigEndian.PutUint16(bytes[27:], l.MsgAge)
	binary.BigEndian.PutUint16(bytes[29:], l.MaxAge)
	binary.BigEndian.PutUint16(bytes[31:], l.HelloTime)
	binary.BigEndian.PutUint16(bytes[33:], l.FwdDelay)
	bytes[35] = l.Version1Length
	binary.BigEndian.PutUint16(bytes[36:], l.OriginatingVlan.Type)
	binary.BigEndian.PutUint16(bytes[38:], l.OriginatingVlan.Length)
	binary.BigEndian.PutUint16(bytes[40:], l.OriginatingVlan.OrigVlan)
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l *BPDUTopology) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(BPDUTopologyLength)
	if err != nil {
		fmt.Println("Error in Serialize to for BPDU Topology")
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:], l.ProtocolId)
	bytes[2] = byte(l.ProtocolVersionId)
	bytes[3] = byte(l.BPDUType)
	return nil
}

func (l *STP) CanDecode() gopacket.LayerClass {
	return LayerTypeBPDU
}

func (l *RSTP) CanDecode() gopacket.LayerClass {
	return LayerTypeBPDU
}

func (l *PVST) CanDecode() gopacket.LayerClass {
	return LayerTypePVST
}

func (l *BPDUTopology) CanDecode() gopacket.LayerClass {
	return LayerTypeBPDU
}

func (f StpFlags) String() (str string) {

	if f&TopoChangeFlag != 0 {
		str += "Topology Change "
	}
	if f&ProposalFlag != 0 {
		str += "Proposal "
	}
	if f&LearningFlag != 0 {
		str += "Learning "
	}
	if f&ForwardingFlag != 0 {
		str += "Forwarding "
	}
	if f&AgreementFlag != 0 {
		str += "Agreement "
	}
	if f&TopoChangeAckFlag != 0 {
		str += "Topology Change Ack "
	}

	role := byte((f & PortRoleFlag) >> 2 & 0x3)
	str += "Role: "
	switch role {
	case RoleRootPort:
		str += "Root Port"
	case RoleDesignatedPort:
		str += "Designated Port"
	case RoleAlternateBackupPort:
		str += "Alternate/Backup Port"
	default:
		str += "Unknown"
	}
	return
}

func (t StpBpduType) String() (str string) {

	switch t {
	case BPDUTypeSTP:
		str += "STP"
	case BPDUTypeRSTP: //BPDUTypePVST
		str += "RSTP"
	case BPDUTypeTopoChange:
		str += "TCN"
	}
	return
}
