// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"github.com/google/gopacket"
	"net"
)

var SlowProtocolDMAC net.HardwareAddr = net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x02}

// SlowProtocol is the layer for SlowProtocol headers.
type SlowProtocol struct {
	BaseLayer
	SubType SlowProtocolType
}

// LayerType returns LayerTypePPP
func (s *SlowProtocol) LayerType() gopacket.LayerType { return LayerTypeSlowProtocol }

func decodeSlowProtocol(data []byte, p gopacket.PacketBuilder) error {
	slow := &SlowProtocol{
		BaseLayer: BaseLayer{data[:1], data[1:]},
		SubType:   SlowProtocolType(data[0]),
	}

	if slow.SubType != SlowProtocolTypeLACP &&
		slow.SubType != SlowProtocolTypeLAMP &&
		slow.SubType != SlowProtocolTypeOAM &&
		slow.SubType != SlowProtocolTypeOSSP {
		return errors.New("Slow Protocol has invalid type")
	}

	p.AddLayer(slow)
	return p.NextDecoder(slow.SubType)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (s *SlowProtocol) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = uint8(s.SubType)
	return nil
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (s *SlowProtocol) NextLayerType() gopacket.LayerType {
	return s.SubType.LayerType()
}
