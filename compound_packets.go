// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"fmt"
	"math"
)

// CompoundPackets packs a SenderReport, a CNAME and a list of feedback packets
// into a sequence of CompoundPackets, each of which marshals to at most
// maxSize bytes.
//
// Every returned CompoundPacket starts with the given SenderReport followed by
// a SourceDescription carrying the CNAME, so each datagram is valid on its own.
// Feedback packets are appended in order and are never split across datagrams;
// each packet is charged its actual MarshalSize against the budget. The
// feedback slice is not modified.
//
// An error is returned if the budget cannot hold the mandatory SenderReport
// and CNAME, if a single feedback packet can never fit, if the feedback list
// is empty, if the CNAME is empty or too long, if a compound packet fails to
// marshal, or if the accounted size overflows.
func CompoundPackets(sender *SenderReport, cname string, feedback []Packet, maxSize int) ([]CompoundPacket, error) {
	if sender == nil {
		return nil, errNilSenderReport
	}
	if len(feedback) == 0 {
		return nil, errNoFeedback
	}
	if len(cname) == 0 || len(cname) > sdesMaxOctetCount {
		return nil, fmt.Errorf("%w: %q", errInvalidCNAME, cname)
	}

	sdes := NewCNAMESourceDescription(sender.SSRC, cname)
	overhead, err := addCompoundSizes(sender.MarshalSize(), sdes.MarshalSize())
	if err != nil {
		return nil, err
	}
	if overhead > maxSize {
		return nil, fmt.Errorf("%w: need at least %d bytes, budget is %d", errBudgetTooSmall, overhead, maxSize)
	}

	var compounds []CompoundPacket
	compound := CompoundPacket{sender, sdes}
	size := overhead

	flush := func() error {
		if _, err := compound.Marshal(); err != nil {
			return fmt.Errorf("rtcp: failed to marshal compound packet: %w", err)
		}
		compounds = append(compounds, compound)
		compound = CompoundPacket{sender, sdes}
		size = overhead

		return nil
	}

	for _, pkt := range feedback {
		if pkt == nil {
			return nil, errNilFeedbackPacket
		}

		pktSize := pkt.MarshalSize()
		single, err := addCompoundSizes(overhead, pktSize)
		if err != nil {
			return nil, err
		}
		if single > maxSize {
			return nil, fmt.Errorf("%w: %T needs %d bytes, budget is %d", errFeedbackTooLarge, pkt, single, maxSize)
		}

		next, err := addCompoundSizes(size, pktSize)
		if err != nil {
			return nil, err
		}
		if next > maxSize {
			if err := flush(); err != nil {
				return nil, err
			}
			next = single
		}

		compound = append(compound, pkt)
		size = next
	}

	if err := flush(); err != nil {
		return nil, err
	}

	return compounds, nil
}

// addCompoundSizes adds two marshaled sizes, guarding against negative values
// and integer overflow.
func addCompoundSizes(a, b int) (int, error) {
	if a < 0 || b < 0 || a > math.MaxInt-b {
		return 0, errCompoundSizeOverflow
	}

	return a + b, nil
}
