// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// 802.1ax-2014 Section 9.4 Distributed Relay Control Protocol
package layers

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/google/gopacket"
)

/*
   MAC address is identified by one of the following
   +------------------------------------------+---------------------+
   | Nearest Customer Bridge group address    |  01-80-C2-00-00-00  |
   +------------------------------------------+---------------------+
   | Nearest Bridge group address             |  01-80-C2-00-00-0E  |
   +------------------------------------------+---------------------+
   | Nearest non-TPMR Bridge group address    |  01-80-C2-00-00-03  |
   +------------------------------------------+---------------------+
*/

// 802.1ax-2014  9.3.3 Protocol Identification  Table 9-5
const (
	// Version
	DRCPVersion1 DRCPVersion = 1
	// SubType
	DRCPSubProtocolDRCP DRCPSubProtocol = 1
	DRCPSubProtocolASCP DRCPSubProtocol = 2
	// TLV upper 6 bits of TLV/Length
	DRCPTLVTypeTerminator                 DRCPTlvTypeLength = 0 << 10
	DRCPTLVTypePortalInfo                 DRCPTlvTypeLength = 1 << 10
	DRCPTLVTypePortalConfigInfo           DRCPTlvTypeLength = 2 << 10
	DRCPTLVTypeDRCPState                  DRCPTlvTypeLength = 3 << 10
	DRCPTLVTypeHomePortsInfo              DRCPTlvTypeLength = 4 << 10
	DRCPTLVTypeNeighborPortsInfo          DRCPTlvTypeLength = 5 << 10
	DRCPTLVTypeOtherPortsInfo             DRCPTlvTypeLength = 6 << 10
	DRCPTLVTypeHomeGatewayVector          DRCPTlvTypeLength = 7 << 10
	DRCPTLVTypeNeighborGatewayVector      DRCPTlvTypeLength = 8 << 10
	DRCPTLVTypeOtherGatewayVector         DRCPTlvTypeLength = 9 << 10
	DRCPTLV2PGatewayConversationVector    DRCPTlvTypeLength = 10 << 10
	DRCPTLV3PGatewayConversationVector1   DRCPTlvTypeLength = 11 << 10
	DRCPTLV3PGatewayConversationVector2   DRCPTlvTypeLength = 12 << 10
	DRCPTLV2PPortConversationVector       DRCPTlvTypeLength = 13 << 10
	DRCPTLV3PPortConversationVector1      DRCPTlvTypeLength = 14 << 10
	DRCPTLV3PPortConversationVector2      DRCPTlvTypeLength = 15 << 10
	DRCPTLVNetworkIPLSharingMethod        DRCPTlvTypeLength = 16 << 10
	DRCPTLVNetworkIPLSharingEncapsulation DRCPTlvTypeLength = 17 << 10
	DRCPTLVOrganizationSpecific           DRCPTlvTypeLength = 18 << 10
	// Length is actually lower of TLV/Length 10 bits, remaining is tlv of 6 bits
	DRCPTlvAndLengthSize                        uint16            = 2
	DRCPTLVTerminatorLength                     DRCPTlvTypeLength = 0
	DRCPTLVPortalInfoLength                     DRCPTlvTypeLength = 16
	DRCPTLVPortalConfigurationInfoLength        DRCPTlvTypeLength = 43
	DRCPTLVStateLength                          DRCPTlvTypeLength = 1
	DRCPTLVHomeGatewayVectorLength_1            DRCPTlvTypeLength = 4
	DRCPTLVHomeGatewayVectorLength_2            DRCPTlvTypeLength = 516
	DRCPTLVNeighborGatewayVectorLength          DRCPTlvTypeLength = 4
	DRCPTLVOtherGatewayVectorLength_1           DRCPTlvTypeLength = 4
	DRCPTLVOtherGatewayVectorLength_2           DRCPTlvTypeLength = 516
	DRCPTLV2PGatewayConversationVectorLength    DRCPTlvTypeLength = 512
	DRCPTLV3PGatewayConversationVector1Length   DRCPTlvTypeLength = 512
	DRCPTLV3PGatewayConversationVector2Length   DRCPTlvTypeLength = 512
	DRCPTLV2PPortConversationVectorLength       DRCPTlvTypeLength = 512
	DRCPTLV3PPortConversationVector1Length      DRCPTlvTypeLength = 512
	DRCPTLV3PPortConversationVector2Length      DRCPTlvTypeLength = 512
	DRCPTLVNetworkIPLSharingMethodLength        DRCPTlvTypeLength = 4
	DRCPTLVNetworkIPLSharingEncapsulationLength DRCPTlvTypeLength = 32

	// DRCP State
	DRCPStateHomeGatewayBit     uint8 = 0
	DRCPStateNeighborGatewayBit uint8 = 1
	DRCPStateOtherGatewayBit    uint8 = 2
	DRCPStateIPPActivity        uint8 = 3
	// short 1, long 0
	DRCPStateDRCPTimeout uint8 = 4
	DRCPStateGatewaySync uint8 = 5
	DRCPStatePortSync    uint8 = 6
	DRCPStateExpired     uint8 = 7

	// DRCP Portal Configuartion Info  Topology State
	DRCPTopologyStatePortalSystemNum                uint8 = 0 // 2 bits
	DRCPTopologyStateNeighborConfPortalSystemNumber       = 2 // 2 bits
	DRCPTopologyState3SystemPortal                        = 4
	DRCPTopologyStateCommonMethods                        = 5
	DRCPTopologyStateReserved                             = 6
	DRCPTopologyStateOtherNonNeighbor                     = 7

	// num topology state bits
	DRCPTopologyStateTwoBitsMask = 0x3
	DRCPTopologyStateOneBitMask  = 0x1

	DRCPLongTimeout  = 0
	DRCPShortTimeout = 1
)

type DRCPTlvTypeLength uint16
type DRCPVersion uint8
type DRCPSubProtocol uint8
type DRCPState uint8
type DRCPTopologyState uint8

// DRCPValue is a TLV + Length value inside a DRCPDU packet layer.
type DRCPValue struct {
	TlvTypeLength DRCPTlvTypeLength
	Value         []byte
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPPortalInfoTlv struct {
	TlvTypeLength  DRCPTlvTypeLength
	AggPriority    uint16
	AggId          [6]uint8
	PortalPriority uint16
	PortalAddr     [6]uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPPortalConfigurationInfoTlv struct {
	TlvTypeLength    DRCPTlvTypeLength
	TopologyState    DRCPTopologyState
	OperAggKey       uint16
	PortAlgorithm    [4]uint8
	GatewayAlgorithm [4]uint8
	PortDigest       [16]uint8
	GatewayDigest    [16]uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPStateTlv struct {
	TlvTypeLength DRCPTlvTypeLength
	State         DRCPState
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPHomePortsInfoTlv struct {
	TlvTypeLength     DRCPTlvTypeLength
	AdminAggKey       uint16
	OperPartnerAggKey uint16
	ActiveHomePorts   []uint32
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPNeighborPortsInfoTlv struct {
	TlvTypeLength       DRCPTlvTypeLength
	AdminAggKey         uint16
	OperPartnerAggKey   uint16
	ActiveNeighborPorts []uint32
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPOtherPortsInfoTlv struct {
	TlvTypeLength     DRCPTlvTypeLength
	AdminAggKey       uint16
	OperPartnerAggKey uint16
	NeighborPorts     []uint32
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPHomeGatewayVectorTlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Sequence      uint32
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPNeighborGatewayVectorTlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Sequence      uint32
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPOtherGatewayVectorTlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Sequence      uint32
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.2
type DRCPTerminatorTlv struct {
	TlvTypeLength DRCPTlvTypeLength
}

// 802.1ax-2014 DRCPDU 9.4.3.3.1 2P Gateway Conversation Vector
type DRCP2PGatewayConversationVectorTlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.3.2 3P Gateway Conversation Vector 1
type DRCP3PGatewayConversationVector1Tlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.3.3 3P Gateway Conversation Vector 2
type DRCP3PGatewayConversationVector2Tlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.3.4 2P Port Conversation Vector
type DRCP2PPortConversationVectorTlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.3.5 3P Port Conversation Vector 1
type DRCP3PPortConversationVector1Tlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.3.6 3P Port Conversation Vector 1
type DRCP3PPortConversationVector2Tlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Vector        []uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.4.1 Network/IPL Sharing Method
type DRCPNetworkIPLSharingMethodTlv struct {
	TlvTypeLength DRCPTlvTypeLength
	Method        [4]uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.4.1 Network/IPL Sharing Method
type DRCPNetworkIPLSharingEncapsulationTlv struct {
	TlvTypeLength  DRCPTlvTypeLength
	IplEncapDigest [16]uint8
	NetEncapDigest [16]uint8
}

// 802.1ax-2014 DRCPDU 9.4.3.2
// Struct will contain all valid TLV's howver they are only valid if the
// TLV type is set properly, this goes for encoding and decoding
type DRCP struct {
	BaseLayer
	SubType                               DRCPSubProtocol
	Version                               DRCPVersion
	PortalInfo                            DRCPPortalInfoTlv
	PortalConfigInfo                      DRCPPortalConfigurationInfoTlv
	State                                 DRCPStateTlv
	HomePortsInfo                         DRCPHomePortsInfoTlv
	NeighborPortsInfo                     DRCPNeighborPortsInfoTlv
	OtherPortsInfo                        DRCPOtherPortsInfoTlv
	HomeGatewayVector                     DRCPHomeGatewayVectorTlv
	NeighborGatewayVector                 DRCPNeighborGatewayVectorTlv
	OtherGatewayVector                    DRCPOtherGatewayVectorTlv
	TwoPortalGatewayConversationVector    DRCP2PGatewayConversationVectorTlv
	ThreePortalGatewayConversationVector1 DRCP3PGatewayConversationVector1Tlv
	ThreePortalGatewayConversationVector2 DRCP3PGatewayConversationVector2Tlv
	TwoPortalPortConversationVector       DRCP2PPortConversationVectorTlv
	ThreePortalPortConversationVector1    DRCP3PPortConversationVector1Tlv
	ThreePortalPortConversationVector2    DRCP3PPortConversationVector2Tlv
	NetworkIPLMethod                      DRCPNetworkIPLSharingMethodTlv
	NetworkIPLEncapsulation               DRCPNetworkIPLSharingEncapsulationTlv
	Terminator                            DRCPTerminatorTlv
}

// LayerType returns LayerTypeDRCP
func (l *DRCP) LayerType() gopacket.LayerType {
	return LayerTypeDRCP
}

// TOOD Function only decodes Version 1
func decodeDRCP(data []byte, p gopacket.PacketBuilder) error {
	drcp := &DRCP{BaseLayer: BaseLayer{Contents: data}}
	var vals []DRCPValue

	drcp.SubType = DRCPSubProtocol(data[0])
	drcp.Version = DRCPVersion(data[1])
	vData := data[2:]
	//fmt.Printf("DECODE: vData %+v\n", vData)
	for len(vData) > 0 {
		val := DRCPValue{TlvTypeLength: DRCPTlvTypeLength(binary.BigEndian.Uint16(vData[0:2]))}
		Length := val.TlvTypeLength.GetLength()
		if Length > 0 {
			//fmt.Printf("DECODE: length %d\n", Length)
			val.Value = vData[DRCPTlvAndLengthSize : Length+DRCPTlvAndLengthSize]
		}
		//fmt.Printf("DECODE: tlv %d length %d value %+v\n", val.TlvTypeLength.GetTlv()>>10, Length, val.Value)
		vals = append(vals, val)
		if val.TlvTypeLength.GetTlv() == DRCPTLVTypeTerminator {
			break
		}
		if len(vData) < int(Length) {
			return fmt.Errorf("Malformed DRCP Header")
		}
		vData = vData[Length+DRCPTlvAndLengthSize:]
	}

	pktEnd := false
	for _, v := range vals {
		switch v.TlvTypeLength.GetTlv() {
		case DRCPTLVTypeTerminator:
			pktEnd = true
		case DRCPTLVTypePortalInfo:
			drcp.PortalInfo = DRCPPortalInfoTlv{
				TlvTypeLength: v.TlvTypeLength,
				AggPriority:   binary.BigEndian.Uint16(v.Value[0:2]),
				AggId: [6]uint8{v.Value[2], v.Value[3], v.Value[4],
					v.Value[5], v.Value[6], v.Value[7]},
				PortalPriority: binary.BigEndian.Uint16(v.Value[8:10]),
				PortalAddr: [6]uint8{v.Value[10], v.Value[11], v.Value[12],
					v.Value[13], v.Value[14], v.Value[15]},
			}
		case DRCPTLVTypePortalConfigInfo:
			drcp.PortalConfigInfo = DRCPPortalConfigurationInfoTlv{
				TlvTypeLength:    v.TlvTypeLength,
				TopologyState:    DRCPTopologyState(v.Value[0]),
				OperAggKey:       binary.BigEndian.Uint16(v.Value[1:3]),
				PortAlgorithm:    [4]uint8{v.Value[3], v.Value[4], v.Value[5], v.Value[6]},
				GatewayAlgorithm: [4]uint8{v.Value[7], v.Value[8], v.Value[9], v.Value[10]},
				PortDigest: [16]uint8{v.Value[11], v.Value[12], v.Value[13], v.Value[14],
					v.Value[15], v.Value[16], v.Value[17], v.Value[18],
					v.Value[19], v.Value[20], v.Value[21], v.Value[22],
					v.Value[23], v.Value[24], v.Value[25], v.Value[26]},
				GatewayDigest: [16]uint8{v.Value[27], v.Value[28], v.Value[29], v.Value[30],
					v.Value[31], v.Value[32], v.Value[33], v.Value[34],
					v.Value[35], v.Value[36], v.Value[37], v.Value[38],
					v.Value[39], v.Value[40], v.Value[41], v.Value[42]},
			}
		case DRCPTLVTypeDRCPState:
			drcp.State = DRCPStateTlv{
				TlvTypeLength: v.TlvTypeLength,
				State:         DRCPState(v.Value[0]),
			}

		case DRCPTLVTypeHomePortsInfo:
			drcp.HomePortsInfo = DRCPHomePortsInfoTlv{
				TlvTypeLength:     v.TlvTypeLength,
				AdminAggKey:       binary.BigEndian.Uint16(v.Value[0:2]),
				OperPartnerAggKey: binary.BigEndian.Uint16(v.Value[2:4]),
			}
			// lets add the ports
			for i := uint16(4); i < v.TlvTypeLength.GetLength(); i += 4 {
				port := binary.BigEndian.Uint32(v.Value[i : i+4])
				drcp.HomePortsInfo.ActiveHomePorts = append(drcp.HomePortsInfo.ActiveHomePorts, port)
			}

		case DRCPTLVTypeNeighborPortsInfo:
			drcp.NeighborPortsInfo = DRCPNeighborPortsInfoTlv{
				TlvTypeLength:     v.TlvTypeLength,
				AdminAggKey:       binary.BigEndian.Uint16(v.Value[0:2]),
				OperPartnerAggKey: binary.BigEndian.Uint16(v.Value[2:4]),
			}
			// lets add the ports
			for i := uint16(4); i < v.TlvTypeLength.GetLength(); i += 4 {
				port := binary.BigEndian.Uint32(v.Value[i : i+4])
				drcp.NeighborPortsInfo.ActiveNeighborPorts = append(drcp.NeighborPortsInfo.ActiveNeighborPorts, port)
			}

		case DRCPTLVTypeOtherPortsInfo:
			drcp.OtherPortsInfo = DRCPOtherPortsInfoTlv{
				TlvTypeLength:     v.TlvTypeLength,
				AdminAggKey:       binary.BigEndian.Uint16(v.Value[0:2]),
				OperPartnerAggKey: binary.BigEndian.Uint16(v.Value[2:4]),
			}
			// lets add the ports
			for i := uint16(4); i < v.TlvTypeLength.GetLength(); i += 4 {
				port := binary.BigEndian.Uint32(v.Value[i : i+4])
				drcp.OtherPortsInfo.NeighborPorts = append(drcp.OtherPortsInfo.NeighborPorts, port)
			}

		case DRCPTLVTypeHomeGatewayVector:
			drcp.HomeGatewayVector = DRCPHomeGatewayVectorTlv{
				TlvTypeLength: v.TlvTypeLength,
				Sequence:      binary.BigEndian.Uint32(v.Value[0:4]),
			}

			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(4); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.HomeGatewayVector.Vector = append(drcp.HomeGatewayVector.Vector, v.Value[i])
			}

		case DRCPTLVTypeNeighborGatewayVector:
			drcp.NeighborGatewayVector = DRCPNeighborGatewayVectorTlv{
				TlvTypeLength: v.TlvTypeLength,
				Sequence:      binary.BigEndian.Uint32(v.Value[0:4]),
			}

		case DRCPTLVTypeOtherGatewayVector:
			drcp.OtherGatewayVector = DRCPOtherGatewayVectorTlv{
				TlvTypeLength: v.TlvTypeLength,
				Sequence:      binary.BigEndian.Uint32(v.Value[0:4]),
			}
			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(4); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.OtherGatewayVector.Vector = append(drcp.OtherGatewayVector.Vector, v.Value[i])
			}

		case DRCPTLV2PGatewayConversationVector:
			drcp.TwoPortalGatewayConversationVector = DRCP2PGatewayConversationVectorTlv{
				TlvTypeLength: v.TlvTypeLength,
			}
			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(0); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.TwoPortalGatewayConversationVector.Vector = append(drcp.TwoPortalGatewayConversationVector.Vector, v.Value[i])

			}
		case DRCPTLV3PGatewayConversationVector1:
			drcp.ThreePortalGatewayConversationVector1 = DRCP3PGatewayConversationVector1Tlv{
				TlvTypeLength: v.TlvTypeLength,
			}
			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(0); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.ThreePortalGatewayConversationVector1.Vector = append(drcp.ThreePortalGatewayConversationVector1.Vector, v.Value[i])
			}
		case DRCPTLV3PGatewayConversationVector2:
			drcp.ThreePortalGatewayConversationVector2 = DRCP3PGatewayConversationVector2Tlv{
				TlvTypeLength: v.TlvTypeLength,
			}
			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(0); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.ThreePortalGatewayConversationVector1.Vector = append(drcp.ThreePortalGatewayConversationVector1.Vector, v.Value[i])
			}
		case DRCPTLV2PPortConversationVector:
			drcp.TwoPortalPortConversationVector = DRCP2PPortConversationVectorTlv{
				TlvTypeLength: v.TlvTypeLength,
			}
			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(0); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.TwoPortalPortConversationVector.Vector = append(drcp.TwoPortalPortConversationVector.Vector, v.Value[i])
			}

		case DRCPTLV3PPortConversationVector1:
			drcp.ThreePortalPortConversationVector1 = DRCP3PPortConversationVector1Tlv{
				TlvTypeLength: v.TlvTypeLength,
			}
			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(0); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.ThreePortalPortConversationVector1.Vector = append(drcp.ThreePortalPortConversationVector1.Vector, v.Value[i])
			}

		case DRCPTLV3PPortConversationVector2:
			drcp.ThreePortalPortConversationVector2 = DRCP3PPortConversationVector2Tlv{
				TlvTypeLength: v.TlvTypeLength,
			}
			// every byte contains the boolean value for 4 conversations
			// conversations id's 0-4095
			for i := uint16(0); i < v.TlvTypeLength.GetLength(); i++ {
				drcp.ThreePortalPortConversationVector2.Vector = append(drcp.ThreePortalPortConversationVector2.Vector, v.Value[i])
			}

		case DRCPTLVNetworkIPLSharingMethod:
			drcp.NetworkIPLMethod = DRCPNetworkIPLSharingMethodTlv{
				TlvTypeLength: v.TlvTypeLength,
				Method:        [4]uint8{v.Value[0], v.Value[1], v.Value[2], v.Value[3]},
			}

		case DRCPTLVNetworkIPLSharingEncapsulation:
			drcp.NetworkIPLEncapsulation = DRCPNetworkIPLSharingEncapsulationTlv{
				TlvTypeLength: v.TlvTypeLength,
				IplEncapDigest: [16]uint8{v.Value[0], v.Value[1], v.Value[2], v.Value[3],
					v.Value[4], v.Value[5], v.Value[6], v.Value[7],
					v.Value[8], v.Value[9], v.Value[10], v.Value[11],
					v.Value[12], v.Value[13], v.Value[14], v.Value[15]},
				NetEncapDigest: [16]uint8{v.Value[16], v.Value[17], v.Value[18], v.Value[19],
					v.Value[20], v.Value[21], v.Value[22], v.Value[23],
					v.Value[24], v.Value[25], v.Value[26], v.Value[27],
					v.Value[28], v.Value[29], v.Value[30], v.Value[31]},
			}

		case DRCPTLVOrganizationSpecific:
			// TODO
		}
	}

	if !pktEnd {
		return fmt.Errorf("Missing mandatory DRCP TLV")
	}
	p.AddLayer(drcp)
	return nil
}

func (d *DRCP) serializePortalInfo(b gopacket.SerializeBuffer) error {

	if d.PortalInfo.TlvTypeLength.GetTlv() != DRCPTLVTypePortalInfo {
		return fmt.Errorf("Error in Serialize to for DRCP PortalInfo TLV incorrect %d", d.PortalInfo.TlvTypeLength.GetTlv())
	}

	bytes, err := b.AppendBytes(int(DRCPTLVPortalInfoLength) + 2)
	if err != nil {
		fmt.Println("Error in Serialize to PortalInfo for DRCP")
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:], uint16(d.PortalInfo.TlvTypeLength))
	binary.BigEndian.PutUint16(bytes[2:], d.PortalInfo.AggPriority)
	bytes[4] = byte(d.PortalInfo.AggId[0])
	bytes[5] = byte(d.PortalInfo.AggId[1])
	bytes[6] = byte(d.PortalInfo.AggId[2])
	bytes[7] = byte(d.PortalInfo.AggId[3])
	bytes[8] = byte(d.PortalInfo.AggId[4])
	bytes[9] = byte(d.PortalInfo.AggId[5])
	binary.BigEndian.PutUint16(bytes[10:], d.PortalInfo.PortalPriority)
	bytes[12] = byte(d.PortalInfo.PortalAddr[0])
	bytes[13] = byte(d.PortalInfo.PortalAddr[1])
	bytes[14] = byte(d.PortalInfo.PortalAddr[2])
	bytes[15] = byte(d.PortalInfo.PortalAddr[3])
	bytes[16] = byte(d.PortalInfo.PortalAddr[4])
	bytes[17] = byte(d.PortalInfo.PortalAddr[5])
	return nil
}

func (d *DRCP) serializePortalConfigInfo(b gopacket.SerializeBuffer) error {

	if d.PortalConfigInfo.TlvTypeLength.GetTlv() != DRCPTLVTypePortalConfigInfo {
		return fmt.Errorf("Error in Serialize to for DRCP PortalConfigInfo TLV incorrect %d", d.PortalConfigInfo.TlvTypeLength.GetTlv())
	}
	bytes, err := b.AppendBytes(int(DRCPTLVPortalConfigurationInfoLength) + 2)
	if err != nil {
		fmt.Println("Error in Serialize PortalConfigInfo for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.PortalConfigInfo.TlvTypeLength))
	bytes[2] = byte(d.PortalConfigInfo.TopologyState)
	binary.BigEndian.PutUint16(bytes[3:], d.PortalConfigInfo.OperAggKey)
	bytes[5] = byte(d.PortalConfigInfo.PortAlgorithm[0])
	bytes[6] = byte(d.PortalConfigInfo.PortAlgorithm[1])
	bytes[7] = byte(d.PortalConfigInfo.PortAlgorithm[2])
	bytes[8] = byte(d.PortalConfigInfo.PortAlgorithm[3])
	bytes[9] = byte(d.PortalConfigInfo.GatewayAlgorithm[0])
	bytes[10] = byte(d.PortalConfigInfo.GatewayAlgorithm[1])
	bytes[11] = byte(d.PortalConfigInfo.GatewayAlgorithm[2])
	bytes[12] = byte(d.PortalConfigInfo.GatewayAlgorithm[3])
	bytes[13] = byte(d.PortalConfigInfo.PortDigest[0])
	bytes[14] = byte(d.PortalConfigInfo.PortDigest[1])
	bytes[15] = byte(d.PortalConfigInfo.PortDigest[2])
	bytes[16] = byte(d.PortalConfigInfo.PortDigest[3])
	bytes[17] = byte(d.PortalConfigInfo.PortDigest[4])
	bytes[18] = byte(d.PortalConfigInfo.PortDigest[5])
	bytes[19] = byte(d.PortalConfigInfo.PortDigest[6])
	bytes[20] = byte(d.PortalConfigInfo.PortDigest[7])
	bytes[21] = byte(d.PortalConfigInfo.PortDigest[8])
	bytes[22] = byte(d.PortalConfigInfo.PortDigest[9])
	bytes[23] = byte(d.PortalConfigInfo.PortDigest[10])
	bytes[24] = byte(d.PortalConfigInfo.PortDigest[11])
	bytes[25] = byte(d.PortalConfigInfo.PortDigest[12])
	bytes[26] = byte(d.PortalConfigInfo.PortDigest[13])
	bytes[27] = byte(d.PortalConfigInfo.PortDigest[14])
	bytes[28] = byte(d.PortalConfigInfo.PortDigest[15])
	bytes[29] = byte(d.PortalConfigInfo.GatewayDigest[0])
	bytes[30] = byte(d.PortalConfigInfo.GatewayDigest[1])
	bytes[31] = byte(d.PortalConfigInfo.GatewayDigest[2])
	bytes[32] = byte(d.PortalConfigInfo.GatewayDigest[3])
	bytes[33] = byte(d.PortalConfigInfo.GatewayDigest[4])
	bytes[34] = byte(d.PortalConfigInfo.GatewayDigest[5])
	bytes[35] = byte(d.PortalConfigInfo.GatewayDigest[6])
	bytes[36] = byte(d.PortalConfigInfo.GatewayDigest[7])
	bytes[37] = byte(d.PortalConfigInfo.GatewayDigest[8])
	bytes[38] = byte(d.PortalConfigInfo.GatewayDigest[9])
	bytes[39] = byte(d.PortalConfigInfo.GatewayDigest[10])
	bytes[40] = byte(d.PortalConfigInfo.GatewayDigest[11])
	bytes[41] = byte(d.PortalConfigInfo.GatewayDigest[12])
	bytes[42] = byte(d.PortalConfigInfo.GatewayDigest[13])
	bytes[43] = byte(d.PortalConfigInfo.GatewayDigest[14])
	bytes[44] = byte(d.PortalConfigInfo.GatewayDigest[15])

	return nil
}

func (d *DRCP) serializeDRCPState(b gopacket.SerializeBuffer) error {

	if d.State.TlvTypeLength.GetTlv() != DRCPTLVTypeDRCPState {
		return fmt.Errorf("Error in Serialize to for DRCP State TLV incorrect %d", d.State.TlvTypeLength.GetTlv())
	}
	bytes, err := b.AppendBytes(int(DRCPTLVStateLength) + 2)
	if err != nil {
		fmt.Println("Error in Serialize State for DRCP")
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:], uint16(d.State.TlvTypeLength))
	bytes[2] = byte(d.State.State)

	return nil
}

func (d *DRCP) serializeHomePortsInfo(b gopacket.SerializeBuffer) error {

	if d.HomePortsInfo.TlvTypeLength.GetTlv() != DRCPTLVTypeHomePortsInfo {
		return fmt.Errorf("Error in Serialize to for DRCP Home Ports Info TLV incorrect %d", d.HomePortsInfo.TlvTypeLength.GetTlv())
	}

	if math.Mod(float64(d.HomePortsInfo.TlvTypeLength.GetLength()), 4) != 0 {
		return fmt.Errorf("Error in Serialize to for DRCP Home Ports Info Length incorrect %d", d.HomePortsInfo.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.HomePortsInfo.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Home Ports Info for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.HomePortsInfo.TlvTypeLength))
	binary.BigEndian.PutUint16(bytes[2:], d.HomePortsInfo.AdminAggKey)
	binary.BigEndian.PutUint16(bytes[4:], d.HomePortsInfo.OperPartnerAggKey)
	for i, j := uint16(6), uint16(0); j < (d.HomePortsInfo.TlvTypeLength.GetLength()-4)/4; i, j = i+4, j+1 {
		binary.BigEndian.PutUint32(bytes[i:], d.HomePortsInfo.ActiveHomePorts[j])
	}

	return nil
}

func (d *DRCP) serializeNeighborPortsInfo(b gopacket.SerializeBuffer) error {

	if d.NeighborPortsInfo.TlvTypeLength.GetTlv() != DRCPTLVTypeNeighborPortsInfo {
		return fmt.Errorf("Error in Serialize to for DRCP Neighbor Ports Info TLV incorrect %d", d.NeighborPortsInfo.TlvTypeLength.GetTlv())
	}

	if math.Mod(float64(d.NeighborPortsInfo.TlvTypeLength.GetLength()), 4) != 0 {
		return fmt.Errorf("Error in Serialize to for DRCP Neighbor Ports Info Length incorrect %d", d.NeighborPortsInfo.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.NeighborPortsInfo.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Neighbor Ports Info for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.NeighborPortsInfo.TlvTypeLength))
	binary.BigEndian.PutUint16(bytes[2:], d.NeighborPortsInfo.AdminAggKey)
	binary.BigEndian.PutUint16(bytes[4:], d.NeighborPortsInfo.OperPartnerAggKey)
	for i, j := uint16(6), uint16(0); j < (d.NeighborPortsInfo.TlvTypeLength.GetLength()-4)/4; i, j = i+4, j+1 {
		binary.BigEndian.PutUint32(bytes[i:], d.NeighborPortsInfo.ActiveNeighborPorts[j])
	}
	return nil
}

func (d *DRCP) serializeOtherPortsInfo(b gopacket.SerializeBuffer) error {

	// ignore assumed that there are less than 3 portals
	if d.OtherPortsInfo.TlvTypeLength.GetTlv() == 0 {
		return nil
	}

	if d.OtherPortsInfo.TlvTypeLength.GetTlv() != DRCPTLVTypeOtherPortsInfo {
		return fmt.Errorf("Error in Serialize to for DRCP Other Ports Info TLV incorrect %d", d.OtherPortsInfo.TlvTypeLength.GetTlv())
	}

	if math.Mod(float64(d.OtherPortsInfo.TlvTypeLength.GetLength()), 4) != 0 {
		return fmt.Errorf("Error in Serialize to for DRCP Other Ports Info Length incorrect %d", d.OtherPortsInfo.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.OtherPortsInfo.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Other Ports Info for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.OtherPortsInfo.TlvTypeLength))
	binary.BigEndian.PutUint16(bytes[2:], d.OtherPortsInfo.AdminAggKey)
	binary.BigEndian.PutUint16(bytes[4:], d.OtherPortsInfo.OperPartnerAggKey)
	for i, j := uint16(6), uint16(0); j < (d.OtherPortsInfo.TlvTypeLength.GetLength()-4)/4; i, j = i+4, j+1 {
		binary.BigEndian.PutUint32(bytes[i:], d.OtherPortsInfo.NeighborPorts[j])
	}

	return nil
}

func (d *DRCP) serializeHomeGatewayVector(b gopacket.SerializeBuffer) error {

	// optional
	if d.HomeGatewayVector.TlvTypeLength.GetTlv() == 0 {
		return nil
	}

	if d.HomeGatewayVector.TlvTypeLength.GetTlv() != DRCPTLVTypeHomeGatewayVector {
		return fmt.Errorf("Error in Serialize to for DRCP Home Gateway Vector TLV incorrect %d", d.HomeGatewayVector.TlvTypeLength.GetTlv())
	}

	if (DRCPTlvTypeLength(d.HomeGatewayVector.TlvTypeLength.GetLength()) == DRCPTLVHomeGatewayVectorLength_1 &&
		len(d.HomeGatewayVector.Vector) != 0) ||
		(DRCPTlvTypeLength(d.HomeGatewayVector.TlvTypeLength.GetLength()) == DRCPTLVHomeGatewayVectorLength_2 &&
			len(d.HomeGatewayVector.Vector) != 512) {
		return fmt.Errorf("Error in Serialize to for DRCP Home Gateway Vector Length incorrect %d", d.HomeGatewayVector.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.HomeGatewayVector.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Home Gateway Vector for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.HomeGatewayVector.TlvTypeLength))
	binary.BigEndian.PutUint32(bytes[2:], d.HomeGatewayVector.Sequence)
	for i, j := uint16(6), uint16(0); j < d.HomeGatewayVector.TlvTypeLength.GetLength()-4; i, j = i+1, j+1 {
		bytes[i] = byte(d.HomeGatewayVector.Vector[j])
	}

	return nil
}

func (d *DRCP) serializeNeighborGatewayVector(b gopacket.SerializeBuffer) error {

	// optional
	if d.NeighborGatewayVector.TlvTypeLength.GetTlv() == 0 {
		return nil
	}

	if d.NeighborGatewayVector.TlvTypeLength.GetTlv() != DRCPTLVTypeNeighborGatewayVector {
		return fmt.Errorf("Error in Serialize to for DRCP Neighbor Gateway Vector TLV incorrect %d", d.NeighborGatewayVector.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.NeighborGatewayVector.TlvTypeLength.GetLength()) != DRCPTLVNeighborGatewayVectorLength {
		return fmt.Errorf("Error in Serialize to for DRCP Neighbor Gateway Vector TLV Length incorrect %d", d.NeighborGatewayVector.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.NeighborGatewayVector.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Neighbor Gateway Vector for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.NeighborGatewayVector.TlvTypeLength))
	binary.BigEndian.PutUint32(bytes[2:], d.NeighborGatewayVector.Sequence)

	return nil
}

func (d *DRCP) serializeOtherGatewayVector(b gopacket.SerializeBuffer) error {

	// ignore assumed that there are less than 3 portals
	if d.OtherGatewayVector.TlvTypeLength.GetTlv() == 0 {
		return nil
	}

	if d.OtherGatewayVector.TlvTypeLength.GetTlv() != DRCPTLVTypeOtherGatewayVector {
		return fmt.Errorf("Error in Serialize to for DRCP Other Gateway Vector TLV incorrect %d", d.OtherGatewayVector.TlvTypeLength.GetTlv())
	}

	if (DRCPTlvTypeLength(d.OtherGatewayVector.TlvTypeLength.GetLength()) == DRCPTLVOtherGatewayVectorLength_1 &&
		len(d.OtherGatewayVector.Vector) != 0) ||
		(DRCPTlvTypeLength(d.OtherGatewayVector.TlvTypeLength.GetLength()) == DRCPTLVOtherGatewayVectorLength_2 &&
			len(d.OtherGatewayVector.Vector) != 512) {
		return fmt.Errorf("Error in Serialize to for DRCP Other Gateway Vector Length incorrect %d", d.OtherGatewayVector.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.OtherGatewayVector.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Other Gateway Vector for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.OtherGatewayVector.TlvTypeLength))
	binary.BigEndian.PutUint32(bytes[2:], d.OtherGatewayVector.Sequence)
	for i, j := uint16(6), uint16(0); j < d.OtherGatewayVector.TlvTypeLength.GetLength()-4; i, j = i+1, j+1 {
		bytes[i] = byte(d.OtherGatewayVector.Vector[j])
	}
	return nil
}

func (d *DRCP) serialize2PGatewayConversationVector(b gopacket.SerializeBuffer) error {

	// optional
	if d.TwoPortalGatewayConversationVector.TlvTypeLength.GetTlv() == DRCPTlvTypeLength(0) {
		return nil
	}

	if d.TwoPortalGatewayConversationVector.TlvTypeLength.GetTlv() != DRCPTLV2PGatewayConversationVector {
		return fmt.Errorf("Error in Serialize to for DRCP 2P Gateway Conversation Vector TLV incorrect %d", d.TwoPortalGatewayConversationVector.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.TwoPortalGatewayConversationVector.TlvTypeLength.GetLength()) != DRCPTLV2PGatewayConversationVectorLength {
		return fmt.Errorf("Error in Serialize to for DRCP 2P Gateway Conversation Vector Length incorrect %d", d.TwoPortalGatewayConversationVector.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.TwoPortalGatewayConversationVector.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize 2P Gateway Conversation Vector for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.TwoPortalGatewayConversationVector.TlvTypeLength))
	for i, j := uint16(2), uint16(0); j < d.TwoPortalGatewayConversationVector.TlvTypeLength.GetLength(); i, j = i+1, j+1 {
		bytes[i] = byte(d.TwoPortalGatewayConversationVector.Vector[j])
	}

	return nil
}

func (d *DRCP) serialize3PGatewayConversationVector1(b gopacket.SerializeBuffer) error {

	// optional
	if d.ThreePortalGatewayConversationVector1.TlvTypeLength.GetTlv() == DRCPTlvTypeLength(0) {
		return nil
	}

	if d.ThreePortalGatewayConversationVector1.TlvTypeLength.GetTlv() != DRCPTLV3PGatewayConversationVector1 {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Gateway Conversation Vector 1 TLV incorrect %d", d.ThreePortalGatewayConversationVector1.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.ThreePortalGatewayConversationVector1.TlvTypeLength.GetLength()) != DRCPTLV3PGatewayConversationVector1Length {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Gateway Conversation Vector 1 Length incorrect %d", d.ThreePortalGatewayConversationVector1.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.ThreePortalGatewayConversationVector1.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize 3P Gateway Conversation Vector 1 for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.ThreePortalGatewayConversationVector1.TlvTypeLength))
	for i, j := uint16(2), uint16(0); j < d.ThreePortalGatewayConversationVector1.TlvTypeLength.GetLength(); i, j = i+1, j+1 {
		bytes[i] = byte(d.ThreePortalGatewayConversationVector1.Vector[j])
	}

	return nil
}

func (d *DRCP) serialize3PGatewayConversationVector2(b gopacket.SerializeBuffer) error {

	// optional
	if d.ThreePortalGatewayConversationVector2.TlvTypeLength.GetTlv() == DRCPTlvTypeLength(0) {
		return nil
	}

	if d.ThreePortalGatewayConversationVector2.TlvTypeLength.GetTlv() != DRCPTLV3PGatewayConversationVector2 {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Gateway Conversation Vector 2 TLV incorrect %d", d.ThreePortalGatewayConversationVector2.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.ThreePortalGatewayConversationVector2.TlvTypeLength.GetLength()) != DRCPTLV3PGatewayConversationVector2Length {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Gateway Conversation Vector 2 Length incorrect %d", d.ThreePortalGatewayConversationVector2.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.ThreePortalGatewayConversationVector2.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize 3P Gateway Conversation Vector 2 for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.ThreePortalGatewayConversationVector2.TlvTypeLength))
	for i, j := uint16(2), uint16(0); j < d.ThreePortalGatewayConversationVector2.TlvTypeLength.GetLength(); i, j = i+1, j+1 {
		bytes[i] = byte(d.ThreePortalGatewayConversationVector2.Vector[j])
	}

	return nil
}

func (d *DRCP) serialize2PPortConversationVector(b gopacket.SerializeBuffer) error {

	// optional
	if d.TwoPortalPortConversationVector.TlvTypeLength.GetTlv() == DRCPTlvTypeLength(0) {
		return nil
	}

	if d.TwoPortalPortConversationVector.TlvTypeLength.GetTlv() != DRCPTLV2PPortConversationVector {
		return fmt.Errorf("Error in Serialize to for DRCP 2P Port Conversation Vector TLV incorrect %d", d.TwoPortalPortConversationVector.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.TwoPortalPortConversationVector.TlvTypeLength.GetLength()) != DRCPTLV2PPortConversationVectorLength {
		return fmt.Errorf("Error in Serialize to for DRCP 2P Port Conversation Vector Length incorrect %d", d.TwoPortalPortConversationVector.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.TwoPortalPortConversationVector.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize 2P Port Conversation Vector for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.TwoPortalPortConversationVector.TlvTypeLength))
	for i, j := uint16(2), uint16(0); j < d.TwoPortalPortConversationVector.TlvTypeLength.GetLength(); i, j = i+1, j+1 {
		bytes[i] = byte(d.TwoPortalPortConversationVector.Vector[j])
	}

	return nil
}

func (d *DRCP) serialize3PPortConversationVector1(b gopacket.SerializeBuffer) error {

	// optional
	if d.ThreePortalPortConversationVector1.TlvTypeLength.GetTlv() == DRCPTlvTypeLength(0) {
		return nil
	}

	if d.ThreePortalPortConversationVector1.TlvTypeLength.GetTlv() != DRCPTLV3PPortConversationVector1 {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Port Conversation Vector 1 TLV incorrect %d", d.ThreePortalPortConversationVector1.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.ThreePortalPortConversationVector1.TlvTypeLength.GetLength()) != DRCPTLV3PPortConversationVector1Length {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Port Conversation Vector 1 Length incorrect %d", d.ThreePortalPortConversationVector1.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.ThreePortalPortConversationVector1.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize 3P Port Conversation Vector 1 for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.ThreePortalPortConversationVector1.TlvTypeLength))
	for i, j := uint16(2), uint16(0); j < d.ThreePortalPortConversationVector1.TlvTypeLength.GetLength(); i, j = i+1, j+1 {
		bytes[i] = byte(d.ThreePortalPortConversationVector1.Vector[j])
	}

	return nil
}

func (d *DRCP) serialize3PPortConversationVector2(b gopacket.SerializeBuffer) error {

	// optional
	if d.ThreePortalPortConversationVector2.TlvTypeLength.GetTlv() == DRCPTlvTypeLength(0) {
		return nil
	}

	if d.ThreePortalPortConversationVector2.TlvTypeLength.GetTlv() != DRCPTLV3PPortConversationVector2 {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Port Conversation Vector 2 TLV incorrect %d", d.ThreePortalPortConversationVector2.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.ThreePortalPortConversationVector2.TlvTypeLength.GetLength()) != DRCPTLV3PPortConversationVector2Length {
		return fmt.Errorf("Error in Serialize to for DRCP 3P Port Conversation Vector 2 Length incorrect %d", d.ThreePortalPortConversationVector2.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.ThreePortalPortConversationVector2.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize 3P Port Conversation Vector 2 for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.ThreePortalPortConversationVector2.TlvTypeLength))
	for i, j := uint16(2), uint16(0); j < d.ThreePortalPortConversationVector2.TlvTypeLength.GetLength(); i, j = i+1, j+1 {
		bytes[i] = byte(d.ThreePortalPortConversationVector2.Vector[j])
	}

	return nil
}

func (d *DRCP) serializeNetworkIPLSharingMethod(b gopacket.SerializeBuffer) error {

	if d.NetworkIPLMethod.TlvTypeLength.GetTlv() != DRCPTLVNetworkIPLSharingMethod {
		return fmt.Errorf("Error in Serialize to for DRCP Network/IPL Sharing Method TLV incorrect %d", d.NetworkIPLMethod.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.NetworkIPLMethod.TlvTypeLength.GetLength()) != DRCPTLVNetworkIPLSharingMethodLength {
		return fmt.Errorf("Error in Serialize to for DRCP Network/IPL Sharing Method Length incorrect %d", d.NetworkIPLMethod.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.NetworkIPLMethod.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Network/IPL Sharing Method for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.NetworkIPLMethod.TlvTypeLength))
	bytes[2] = byte(d.NetworkIPLMethod.Method[0])
	bytes[3] = byte(d.NetworkIPLMethod.Method[1])
	bytes[4] = byte(d.NetworkIPLMethod.Method[2])
	bytes[5] = byte(d.NetworkIPLMethod.Method[3])

	return nil
}

func (d *DRCP) serializeNetworkIPLSharingEncapsulation(b gopacket.SerializeBuffer) error {

	// optional
	if d.NetworkIPLEncapsulation.TlvTypeLength.GetTlv() == DRCPTlvTypeLength(0) {
		return nil
	}

	if d.NetworkIPLEncapsulation.TlvTypeLength.GetTlv() != DRCPTLVNetworkIPLSharingEncapsulation {
		return fmt.Errorf("Error in Serialize to for DRCP Network/IPL Sharing Encapsulation TLV incorrect %d", d.NetworkIPLEncapsulation.TlvTypeLength.GetTlv())
	}

	if DRCPTlvTypeLength(d.NetworkIPLEncapsulation.TlvTypeLength.GetLength()) != DRCPTLVNetworkIPLSharingEncapsulationLength {
		return fmt.Errorf("Error in Serialize to for DRCP Network/IPL Sharing Encapsulation Length incorrect %d", d.NetworkIPLEncapsulation.TlvTypeLength.GetLength())
	}

	bytes, err := b.AppendBytes(int(d.NetworkIPLEncapsulation.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize Network/IPL Sharing Method for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.NetworkIPLEncapsulation.TlvTypeLength))
	bytes[2] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[0])
	bytes[3] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[1])
	bytes[4] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[2])
	bytes[5] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[3])
	bytes[6] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[4])
	bytes[7] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[5])
	bytes[8] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[6])
	bytes[9] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[7])
	bytes[10] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[8])
	bytes[11] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[9])
	bytes[12] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[10])
	bytes[13] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[11])
	bytes[14] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[12])
	bytes[15] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[13])
	bytes[16] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[14])
	bytes[17] = byte(d.NetworkIPLEncapsulation.IplEncapDigest[15])
	bytes[18] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[0])
	bytes[19] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[1])
	bytes[20] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[2])
	bytes[21] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[3])
	bytes[22] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[4])
	bytes[23] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[5])
	bytes[24] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[6])
	bytes[25] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[7])
	bytes[26] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[8])
	bytes[27] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[9])
	bytes[28] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[10])
	bytes[29] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[11])
	bytes[30] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[12])
	bytes[31] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[13])
	bytes[32] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[14])
	bytes[33] = byte(d.NetworkIPLEncapsulation.NetEncapDigest[15])

	return nil
}

func (d *DRCP) serializeTerminator(b gopacket.SerializeBuffer) error {

	if d.Terminator.TlvTypeLength.GetTlv() != DRCPTLVTypeTerminator {
		return fmt.Errorf("Error in Serialize to for DRCP Terminator TLV incorrect %d", d.Terminator.TlvTypeLength.GetTlv())
	}

	bytes, err := b.AppendBytes(int(d.Terminator.TlvTypeLength.GetLength()) + 2)
	if err != nil {
		fmt.Println("Error in Serialize PortalConfigInfo for DRCP")
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(d.NetworkIPLEncapsulation.TlvTypeLength))

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (d *DRCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// TODO only supports Version 1
	/*
		DRCPTLVTerminatorLength                     uint8 = 0
		DRCPTLVPortalInfoLength                     uint8 = 16
		DRCPTLVPortalConfigurationInfoLength        uint8 = 16
		DRCPTLVStateLength                          uint8 = 43
		DRCPTLVHomeGatewayVectorLength_1            uint8 = 4
		DRCPTLVHomeGatewayVectorLength_2            uint8 = 516
		DRCPTLVNeighborGatewayVectorLength          uint8 = 4
		DRCPTLVOtherGatewayVectorLength_1           uint8 = 4
		DRCPTLVOtherGatewayVectorLength_2           uint8 = 516
		DRCPTLV2PGatewayConversationVectorLength    uint8 = 512
		DRCPTLV3PGatewayConversationVector1Length   uint8 = 512
		DRCPTLV3PGatewayConversationVector2Length   uint8 = 512
		DRCPTLV2PPortConversationVectorLength       uint8 = 512
		DRCPTLV3PPortConversationVector1Length      uint8 = 512
		DRCPTLV3PPortConversationVector2Length      uint8 = 512
		DRCPTLVNetworkIPLSharingMethodLength        uint8 = 4
		DRCPTLVNetworkIPLSharingEncapsulationLength uint8 = 32
	*/
	bytes, err := b.PrependBytes(2)
	if err != nil {
		fmt.Println("Error in Serialize to for DRCP")
		return err
	}

	/*
		DRCPTLVTypeTerminator                 DRCPTLVType = 0
		DRCPTLVTypePortalInfo                 DRCPTLVType = 1
		DRCPTLVTypePortalConfigInfo           DRCPTLVType = 2
		DRCPTLVTypeDRCPState                  DRCPTLVType = 3
		DRCPTLVTypeHomePortsInfo              DRCPTLVType = 4
		DRCPTLVTypeNeighborPortsInfo          DRCPTLVType = 5
		DRCPTLVTypeOtherPortsInfo             DRCPTLVType = 6
		DRCPTLVTypeHomeGatewayVector          DRCPTLVType = 7
		DRCPTLVTypeNeighborGatewayVector      DRCPTLVType = 8
		DRCPTLVTypeOtherGatewayVector         DRCPTLVType = 9
		DRCPTLV2PGatewayConversationVector    DRCPTLVType = 10
		DRCPTLV3PGatewayConversationVector1   DRCPTLVType = 11
		DRCPTLV3PGatewayConversationVector2   DRCPTLVType = 12
		DRCPTLV2PPortConversationVector       DRCPTLVType = 13
		DRCPTLV3PPortConversationVector1      DRCPTLVType = 14
		DRCPTLV3PPortConversationVector2      DRCPTLVType = 15
		DRCPTLVNetworkIPLSharingMethod        DRCPTLVType = 16
		DRCPTLVNetworkIPLSharingEncapsulation DRCPTLVType = 17
		DRCPTLVOrganizationSpecific           DRCPTLVType = 18
	*/

	bytes[0] = byte(d.SubType)
	bytes[1] = byte(d.Version)
	err = d.serializePortalInfo(b)
	if err != nil {
		return err
	}
	err = d.serializePortalConfigInfo(b)
	if err != nil {
		return err
	}
	err = d.serializeDRCPState(b)
	if err != nil {
		return err
	}
	err = d.serializeHomePortsInfo(b)
	if err != nil {
		return err
	}
	err = d.serializeNeighborPortsInfo(b)
	if err != nil {
		return err
	}
	err = d.serializeOtherPortsInfo(b)
	if err != nil {
		return err
	}
	err = d.serializeHomeGatewayVector(b)
	if err != nil {
		return err
	}
	err = d.serializeNeighborGatewayVector(b)
	if err != nil {
		return err
	}
	err = d.serializeOtherGatewayVector(b)
	if err != nil {
		return err
	}
	err = d.serialize2PGatewayConversationVector(b)
	if err != nil {
		return err
	}
	err = d.serialize3PGatewayConversationVector1(b)
	if err != nil {
		return err
	}
	err = d.serialize3PGatewayConversationVector2(b)
	if err != nil {
		return err
	}
	err = d.serialize2PPortConversationVector(b)
	if err != nil {
		return err
	}
	err = d.serialize3PPortConversationVector1(b)
	if err != nil {
		return err
	}
	err = d.serialize3PPortConversationVector2(b)
	if err != nil {
		return err
	}
	err = d.serializeNetworkIPLSharingMethod(b)
	if err != nil {
		return err
	}
	err = d.serializeNetworkIPLSharingEncapsulation(b)
	if err != nil {
		return err
	}
	err = d.serializeTerminator(b)
	if err != nil {
		return err
	}
	return nil
}

func (l *DRCP) CanDecode() gopacket.LayerClass {
	return LayerTypeDRCP
}

func (s *DRCPState) SetState(statetype uint8) {
	*s |= (1 << statetype)
}
func (s *DRCPState) ClearState(statetype uint8) {
	*s &= ^(1 << statetype)
}

func (s *DRCPState) GetState(statetype uint8) bool {
	return ((*s >> statetype) & 0x1) == 1
}

func (s *DRCPTopologyState) SetState(statetype, value uint8) {
	*s |= DRCPTopologyState(value << statetype)
}

func (s *DRCPTopologyState) ClearState(statetype, value uint8) {
	*s &= DRCPTopologyState(^(value << statetype))
}

func (s *DRCPTopologyState) GetState(statetype uint8) (val DRCPTopologyState) {

	if statetype == DRCPTopologyStateNeighborConfPortalSystemNumber ||
		statetype == DRCPTopologyStatePortalSystemNum {
		val = DRCPTopologyState((*s >> statetype) & DRCPTopologyStateTwoBitsMask)
	} else {
		val = DRCPTopologyState((*s >> statetype) & DRCPTopologyStateOneBitMask)
	}
	return val
}

func (s *DRCPTopologyState) String() (rs string) {
	rs = ""
	rs += fmt.Sprintf("Portal System Number: %s ", ((*s >> DRCPTopologyStatePortalSystemNum) & 0x3))
	rs += fmt.Sprintf("Neighbor Conf Portal System Number: %s ", ((*s >> DRCPTopologyStateNeighborConfPortalSystemNumber) & 0x3))
	rs += fmt.Sprintf("3 System Portal: %t ", ((*s>>DRCPTopologyState3SystemPortal)&0x1) == 1)
	rs += fmt.Sprintf("Common Methods: %t ", ((*s>>DRCPTopologyStateCommonMethods)&0x1) == 1)
	rs += fmt.Sprintf("Other Non Neighbor: %t ", ((*s>>DRCPTopologyStateOtherNonNeighbor)&0x1) == 1)
	return rs
}

func (s *DRCPState) String() (rs string) {
	rs = ""
	if s.GetState(DRCPStateHomeGatewayBit) {
		rs += "Home Gateway, "
	}
	if s.GetState(DRCPStateNeighborGatewayBit) {
		rs += "Neighbor Gateway, "
	}
	if s.GetState(DRCPStateOtherGatewayBit) {
		rs += "Other Gateway, "
	}
	if s.GetState(DRCPStateIPPActivity) {
		rs += "IPP Activity, "
	}
	if s.GetState(DRCPStateDRCPTimeout) {
		rs += "DRCP Timeout SHORT, "
	} else {
		rs += "DRCP Timeout LONG, "
	}
	if s.GetState(DRCPStateGatewaySync) {
		rs += "Gateway Sync, "
	}
	if s.GetState(DRCPStatePortSync) {
		rs += "Port Sync, "
	}
	if s.GetState(DRCPStateExpired) {
		rs += "Expired"
	}
	return rs
}

func (v *DRCPTlvTypeLength) String() (s string) {
	s = "TLV: "
	switch v.GetTlv() {
	case DRCPTLVTypeTerminator:
		s += "TLV Terminator"
	case DRCPTLVTypePortalInfo:
		s += "Portal Info"
	case DRCPTLVTypePortalConfigInfo:
		s += "Portal Configuration Info"
	case DRCPTLVTypeDRCPState:
		s += "DRCP State"
	case DRCPTLVTypeHomePortsInfo:
		s += "Home Ports Info"
	case DRCPTLVTypeNeighborPortsInfo:
		s += "Neighbor Ports Info"
	case DRCPTLVTypeOtherPortsInfo:
		s += "Other Ports Info"
	case DRCPTLVTypeHomeGatewayVector:
		s += "Home Gateway Vector"
	case DRCPTLVTypeNeighborGatewayVector:
		s += "Neighbor Gateway Vector"
	case DRCPTLVTypeOtherGatewayVector:
		s += "Other Gateway Vector"
	case DRCPTLV2PGatewayConversationVector:
		s += "2P Gateway Conversation Vector"
	case DRCPTLV3PGatewayConversationVector1:
		s += "3P Gateway Conversation Vector 1"
	case DRCPTLV3PGatewayConversationVector2:
		s += "3P Gateway Conversation Vector 2"
	case DRCPTLV2PPortConversationVector:
		s += "2P Port Conversation Vector"
	case DRCPTLV3PPortConversationVector1:
		s += "3P Port Conversation Vector 1"
	case DRCPTLV3PPortConversationVector2:
		s += "3P Port Conversation Vector 2"
	case DRCPTLVNetworkIPLSharingMethod:
		s += "Network/IPL Sharing Method"
	case DRCPTLVNetworkIPLSharingEncapsulation:
		s += "Network/IPL Sharing Encapsulation"
	case DRCPTLVOrganizationSpecific:
		s += "Organization Specific"
	default:
		s += "Unknown"
	}
	s += fmt.Sprintf("Length: %d", v.GetLength())
	return s
}

func (v *DRCPTlvTypeLength) SetTlv(tlv uint16) {
	*v |= DRCPTlvTypeLength(tlv)
}

func (v *DRCPTlvTypeLength) SetLength(length uint16) {
	*v |= DRCPTlvTypeLength(length)
}

func (v *DRCPTlvTypeLength) GetTlv() DRCPTlvTypeLength {
	return *v & 0xfC00
}

func (v *DRCPTlvTypeLength) GetLength() uint16 {
	return uint16(*v) & 0x3ff
}
