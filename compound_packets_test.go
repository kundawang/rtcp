// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compoundPacketsTestFeedback() []Packet {
	return []Packet{
		&TransportLayerNack{
			SenderSSRC: 1,
			MediaSSRC:  2,
			Nacks: []NackPair{
				{PacketID: 10, LostPackets: 0x01},
				{PacketID: 20, LostPackets: 0x02},
			},
		},
		&PictureLossIndication{SenderSSRC: 1, MediaSSRC: 2},
		&ExtendedReport{
			SenderSSRC: 1,
			Reports: []ReportBlock{
				&ReceiverReferenceTimeReportBlock{NTPTimestamp: 0x0102030405060708},
			},
		},
		&TransportLayerNack{
			SenderSSRC: 1,
			MediaSSRC:  2,
			Nacks:      []NackPair{{PacketID: 30, LostPackets: 0x04}},
		},
		&PictureLossIndication{SenderSSRC: 1, MediaSSRC: 3},
	}
}

func TestCompoundPackets(t *testing.T) {
	sender := &SenderReport{SSRC: 1, NTPTime: 0x0102030405060708, RTPTime: 9, PacketCount: 10, OctetCount: 11}
	feedback := compoundPacketsTestFeedback()
	original := append([]Packet(nil), feedback...)

	overhead := sender.MarshalSize() + NewCNAMESourceDescription(sender.SSRC, "cname").MarshalSize()
	// Budget exactly fits the SR, the CNAME SDES and the first two feedback
	// packets, forcing the rest into further datagrams.
	budget := overhead + feedback[0].MarshalSize() + feedback[1].MarshalSize()

	compounds, err := CompoundPackets(sender, "cname", feedback, budget)
	require.NoError(t, err)
	require.Len(t, compounds, 3)

	// Feedback is packed in order, never split: [NACK, PLI], [XR], [NACK, PLI].
	require.Len(t, compounds[0], 2+2)
	require.Len(t, compounds[1], 2+1)
	require.Len(t, compounds[2], 2+2)

	var repacked []Packet
	for _, compound := range compounds {
		// Every datagram is self-contained and valid.
		require.IsType(t, (*SenderReport)(nil), compound[0])
		sdes, ok := compound[1].(*SourceDescription)
		require.True(t, ok)
		require.Equal(t, "cname", sdes.Chunks[0].Items[0].Text)

		assert.NoError(t, compound.Validate())
		assert.LessOrEqual(t, compound.MarshalSize(), budget)

		raw, err := compound.Marshal()
		assert.NoError(t, err)
		assert.Len(t, raw, compound.MarshalSize())

		repacked = append(repacked, compound[2:]...)
	}

	// Exact sizes of each datagram.
	assert.Equal(t, budget, compounds[0].MarshalSize())
	assert.Equal(t, overhead+feedback[2].MarshalSize(), compounds[1].MarshalSize())
	assert.Equal(t, overhead+feedback[3].MarshalSize()+feedback[4].MarshalSize(), compounds[2].MarshalSize())

	// Order is preserved across datagrams.
	assert.Equal(t, original, repacked)

	// The original feedback slice is not modified.
	assert.Equal(t, original, feedback)
}

func TestCompoundPacketsSingleDatagram(t *testing.T) {
	sender := &SenderReport{SSRC: 1}
	feedback := compoundPacketsTestFeedback()

	total := sender.MarshalSize() + NewCNAMESourceDescription(1, "cname").MarshalSize()
	for _, pkt := range feedback {
		total += pkt.MarshalSize()
	}

	compounds, err := CompoundPackets(sender, "cname", feedback, total)
	require.NoError(t, err)
	require.Len(t, compounds, 1)
	assert.Equal(t, total, compounds[0].MarshalSize())
	assert.NoError(t, compounds[0].Validate())
}

func TestCompoundPacketsErrors(t *testing.T) {
	sender := &SenderReport{SSRC: 1}
	feedback := compoundPacketsTestFeedback()
	overhead := sender.MarshalSize() + NewCNAMESourceDescription(1, "cname").MarshalSize()
	budget := overhead + 64

	t.Run("nil sender report", func(t *testing.T) {
		_, err := CompoundPackets(nil, "cname", feedback, budget)
		assert.ErrorIs(t, err, errNilSenderReport)
	})

	t.Run("empty feedback", func(t *testing.T) {
		_, err := CompoundPackets(sender, "cname", nil, budget)
		assert.ErrorIs(t, err, errNoFeedback)
	})

	t.Run("invalid CNAME", func(t *testing.T) {
		_, err := CompoundPackets(sender, "", feedback, budget)
		assert.ErrorIs(t, err, errInvalidCNAME)

		_, err = CompoundPackets(sender, strings.Repeat("a", sdesMaxOctetCount+1), feedback, budget)
		assert.ErrorIs(t, err, errInvalidCNAME)
	})

	t.Run("budget too small for header", func(t *testing.T) {
		_, err := CompoundPackets(sender, "cname", feedback, overhead-1)
		assert.ErrorIs(t, err, errBudgetTooSmall)

		_, err = CompoundPackets(sender, "cname", feedback, 0)
		assert.ErrorIs(t, err, errBudgetTooSmall)
	})

	t.Run("single packet exceeds budget", func(t *testing.T) {
		huge := &TransportLayerNack{SenderSSRC: 1, MediaSSRC: 2, Nacks: make([]NackPair, 100)}
		_, err := CompoundPackets(sender, "cname", []Packet{huge}, budget)
		assert.ErrorIs(t, err, errFeedbackTooLarge)
	})

	t.Run("nil feedback packet", func(t *testing.T) {
		//nolint:staticcheck // intentionally passing a nil packet
		_, err := CompoundPackets(sender, "cname", []Packet{nil}, budget)
		assert.ErrorIs(t, err, errNilFeedbackPacket)
	})

	t.Run("size overflow", func(t *testing.T) {
		_, err := CompoundPackets(sender, "cname", []Packet{hugeSizePacket{}}, budget)
		assert.ErrorIs(t, err, errCompoundSizeOverflow)
	})

	t.Run("marshal failure", func(t *testing.T) {
		_, err := CompoundPackets(sender, "cname", []Packet{failingPacket{}}, budget)
		assert.ErrorIs(t, err, errFailingPacketMarshal)
	})
}

var errFailingPacketMarshal = errors.New("rtcp: test marshal failure")

// failingPacket marshals with an error while reporting a valid size.
type failingPacket struct{}

func (failingPacket) DestinationSSRC() []uint32 { return nil }
func (failingPacket) Marshal() ([]byte, error)  { return nil, errFailingPacketMarshal }
func (failingPacket) Unmarshal([]byte) error    { return nil }
func (failingPacket) MarshalSize() int          { return 4 }

// hugeSizePacket reports a MarshalSize that overflows size accounting.
type hugeSizePacket struct{}

func (hugeSizePacket) DestinationSSRC() []uint32 { return nil }
func (hugeSizePacket) Marshal() ([]byte, error)  { return nil, nil }
func (hugeSizePacket) Unmarshal([]byte) error    { return nil }
func (hugeSizePacket) MarshalSize() int          { return math.MaxInt }
