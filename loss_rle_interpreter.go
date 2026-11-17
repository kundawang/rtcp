// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// This file implements an interpreter for the traces carried by Loss RLE
// (RFC 3611, section 4.1) and Duplicate RLE (RFC 3611, section 4.2) report
// blocks.
//
// The report block types only expose the chunks as they arrived on the wire.
// A consumer that wants to know which packets were received, lost or
// duplicated has to expand the chunks into a trace, translate the 16 bit
// sequence numbers into a coordinate that keeps increasing across a
// wraparound, and merge repeated reports of the same sequence number without
// counting the same packet twice.
//
// LossRLEInterpreter does that. It is fed with *ExtendedReport packets in the
// order that they are received (which need not be sequence-number order) and
// reports received, lost and duplicate intervals per SSRC plus the loss rate
// of each reporting window.

// RLEStatus is the interpreted state of one sequence number.
type RLEStatus uint8

const (
	// RLEStatusUnknown means that no report has described this sequence
	// number. This is the state of thinned-out sequence numbers and of gaps
	// between reporting windows.
	RLEStatusUnknown RLEStatus = iota
	// RLEStatusReceived means the trace encoded a one for the sequence number:
	// at least one packet with that number was received.
	RLEStatusReceived
	// RLEStatusLost means a Loss RLE trace encoded a zero for the sequence
	// number: no packet with that number had been received at report time.
	RLEStatusLost
	// RLEStatusDuplicate means a Duplicate RLE trace encoded a zero for the
	// sequence number: more than one packet with that number was received.
	RLEStatusDuplicate
)

// String returns a human readable name for the status.
func (s RLEStatus) String() string {
	switch s {
	case RLEStatusUnknown:
		return "unknown"
	case RLEStatusReceived:
		return "received"
	case RLEStatusLost:
		return "lost"
	case RLEStatusDuplicate:
		return "duplicate"
	}

	return fmt.Sprintf("invalid status %d", uint8(s))
}

// RLEInterval is a half-open interval of sequence numbers that share one
// RLEStatus. Start is inclusive and End is exclusive. Both are extended
// sequence numbers: they keep increasing across a 16 bit wraparound, so an
// interval that spans the wrap is one interval rather than two. The low 16
// bits of Start and End are the sequence numbers on the wire.
type RLEInterval struct {
	Status RLEStatus
	// Start is the extended sequence number of the first packet.
	Start uint64
	// End is the extended sequence number one past the last packet.
	End uint64
}

// Len returns the number of sequence numbers covered by the interval.
func (i RLEInterval) Len() uint64 {
	if i.End <= i.Start {
		return 0
	}

	return i.End - i.Start
}

// SeqStart returns the 16 bit sequence number of the first packet.
func (i RLEInterval) SeqStart() uint16 {
	return uint16(i.Start & 0xFFFF) //nolint:gosec // G115
}

// SeqEnd returns the 16 bit sequence number one past the last packet.
func (i RLEInterval) SeqEnd() uint16 {
	return uint16(i.End & 0xFFFF) //nolint:gosec // G115
}

// String returns a human readable form of the interval.
func (i RLEInterval) String() string {
	if i.Len() == 0 {
		return fmt.Sprintf("%s [%d, %d)", i.Status, i.Start, i.End)
	}

	return fmt.Sprintf("%s [%d-%d] (%d packets)", i.Status, i.Start, i.End-1, i.Len())
}

// RLEWindow is the interpreted trace of a single Loss RLE or Duplicate RLE
// report block. It covers begin_seq through end_seq-1 (modulo 65536), with
// thinning applied.
//
// Begin and End are extended sequence numbers. BeginSeq and EndSeq are the
// values as reported, so EndSeq may be numerically smaller than BeginSeq after
// a wraparound. Reported is the length of the thinned trace, i.e. how many
// sequence numbers the chunks actually describe.
//
// For a Loss RLE window Received, Lost and LossRate describe the trace. For a
// Duplicate RLE window Received and Lost are zero, Duplicates counts the zero
// bits (sequence numbers with a duplicate) and LossRate is zero, because a
// Duplicate RLE trace says nothing about receipt or loss.
type RLEWindow struct {
	SSRC        uint32
	SenderSSRC  uint32
	IsDuplicate bool
	Thinning    uint8
	BeginSeq    uint16
	EndSeq      uint16
	Begin       uint64
	End         uint64
	Reported    uint64
	Received    uint64
	Lost        uint64
	Duplicates  uint64
	LossRate    float64
}

// String returns a human readable form of the window.
func (w RLEWindow) String() string {
	kind := "loss"
	if w.IsDuplicate {
		kind = "duplicate"
	}

	return fmt.Sprintf("SSRC 0x%X %s window seq %d-%d T=%d: received=%d lost=%d duplicates=%d loss_rate=%.3f",
		w.SSRC, kind, w.BeginSeq, w.EndSeq, w.Thinning, w.Received, w.Lost, w.Duplicates, w.LossRate)
}

// RLEStream holds the interpreted intervals of one SSRC, merged across every
// report that described it.
//
// Intervals are sorted by Start and never overlap or touch: contiguous
// sequence numbers with the same status are merged, and a sequence number
// that a later report describes differently has a single, final status.
// Windows preserves one entry per interpreted report block, in interpretation
// order, so that per-window statistics remain available even when windows
// overlap.
type RLEStream struct {
	// SSRC is the source these intervals describe.
	SSRC uint32
	// Intervals are the merged, non-overlapping intervals in increasing
	// extended sequence number order.
	Intervals []RLEInterval
	// Windows are the interpreted report blocks for this SSRC, in the order
	// they were interpreted.
	Windows []RLEWindow
	// Received, Lost and Duplicates count the sequence numbers whose final
	// status is received, lost or duplicate. A sequence number mentioned by
	// several reports is counted once.
	Received   uint64
	Lost       uint64
	Duplicates uint64
}

// Observed returns the number of sequence numbers whose final status is known.
func (s RLEStream) Observed() uint64 {
	return s.Received + s.Lost + s.Duplicates
}

// LossRate returns Lost divided by the number of observed sequence numbers. A
// duplicate sequence number was received, so it belongs in the denominator.
// The rate is zero when no sequence number was observed.
func (s RLEStream) LossRate() float64 {
	return ratio(s.Lost, s.Observed())
}

// WindowLossRate returns the loss rate of each reporting window, in order.
// Duplicate RLE windows report zero.
func (s RLEStream) WindowLossRate() []float64 {
	rates := make([]float64, len(s.Windows))
	for i, window := range s.Windows {
		rates[i] = window.LossRate
	}

	return rates
}

// LossIntervals returns only the lost intervals.
func (s RLEStream) LossIntervals() []RLEInterval {
	return s.intervalsWithStatus(RLEStatusLost)
}

// ReceivedIntervals returns only the received intervals.
func (s RLEStream) ReceivedIntervals() []RLEInterval {
	return s.intervalsWithStatus(RLEStatusReceived)
}

// DuplicateIntervals returns only the duplicate intervals.
func (s RLEStream) DuplicateIntervals() []RLEInterval {
	return s.intervalsWithStatus(RLEStatusDuplicate)
}

func (s RLEStream) intervalsWithStatus(status RLEStatus) []RLEInterval {
	intervals := make([]RLEInterval, 0, len(s.Intervals))
	for _, interval := range s.Intervals {
		if interval.Status == status {
			intervals = append(intervals, interval)
		}
	}

	return intervals
}

// String returns a human readable form of the stream.
func (s RLEStream) String() string {
	var out strings.Builder
	fmt.Fprintf(&out, "SSRC 0x%X: received=%d lost=%d duplicates=%d loss_rate=%.3f\n",
		s.SSRC, s.Received, s.Lost, s.Duplicates, s.LossRate())
	for _, interval := range s.Intervals {
		fmt.Fprintf(&out, "\t%v\n", interval)
	}

	return out.String()
}

func ratio(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}

	return float64(numerator) / float64(denominator)
}

const (
	rleSeqSpace = 1 << 16
	// rleInitialSeq seeds the extended sequence space in its middle so that a
	// report may be up to 32768 sequence numbers older than the first one
	// without leaving the space. The low 16 bits are zero, so OR-ing a 16 bit
	// sequence number into it is the same as adding it.
	rleInitialSeq = 1 << 31
)

// extendedSeq places the 16 bit sequence number seq in the extended sequence
// space using reference, the most recent position seen for the source, as the
// starting point. The RFC 3611 appendix A.1 heuristic is used: the candidate
// within 32768 positions of reference is selected. At exactly 32768 positions
// the RFC prose and its sample code disagree; the prose is followed and the
// candidate in the reference's own 16 bit space is kept, which is the
// interpretation that requires no rollover.
func extendedSeq(seq uint16, reference uint64) uint64 {
	base := reference &^ 0xFFFF
	candidate := base | uint64(seq)
	delta := int64(candidate) - int64(reference) //nolint:gosec // G115 bounded by 16 bits
	switch {
	case delta > 0x8000:
		candidate -= rleSeqSpace
	case delta < -0x8000:
		candidate += rleSeqSpace
	}

	return candidate
}

// rlePosition is the state accumulated for one extended sequence number.
// Receipt and duplication are tracked separately because the two report block
// types describe different properties of the same sequence number.
type rlePosition struct {
	receipt   RLEStatus // RLEStatusUnknown, RLEStatusReceived or RLEStatusLost
	duplicate bool
}

// status resolves the accumulated state to a single interval status. A
// duplicate proves that the packet was received at least twice, so it takes
// precedence over a plain receipt or loss.
func (p rlePosition) status() RLEStatus {
	switch {
	case p.duplicate:
		return RLEStatusDuplicate
	case p.receipt == RLEStatusLost:
		return RLEStatusLost
	case p.receipt == RLEStatusReceived:
		return RLEStatusReceived
	default:
		return RLEStatusUnknown
	}
}

// lossRLE is the state kept for one SSRC.
type lossRLE struct {
	ref       uint64
	refSet    bool
	positions map[uint64]rlePosition
	windows   []RLEWindow
}

// LossRLEInterpreter interprets Loss RLE and Duplicate RLE report blocks across
// a series of ExtendedReport packets.
//
// Packets may be interpreted in any arrival order. Sequence numbers are
// translated to extended sequence numbers relative to the most recent sequence
// number seen for the SSRC (RFC 3611, appendix A.1), so reports that overlap
// and reports that straddle a 16 bit wraparound are merged in one coordinate
// space. A report more than 32768 sequence numbers away from everything seen
// for the SSRC is inherently ambiguous, as RFC 3611 notes; the nearest
// placement is chosen deterministically.
//
// Conflict policy, chosen so that reports may arrive in any order:
//
//   - Receipt is monotonic. A loss means only that no packet had arrived at
//     report time, while a receipt is positive evidence that one did, and
//     evidence cannot be undone by a later (or older) report of absence. A
//     sequence number reported lost and later reported received therefore
//     becomes received, as RFC 3611 permits, and a receipt followed by a loss
//     stays received. The result does not depend on the order in which the
//     reports arrive.
//   - Duplicate state is sticky. Duplicate RLE blocks describe different
//     reporting periods, and "no duplicate observed" in a later period is not
//     evidence against an earlier duplicate. Each sequence number contributes
//     to the duplicate count at most once.
//   - A duplicate proves receipt two or more times, so a sequence number that
//     is both marked as duplicated and reported lost resolves to duplicate,
//     and is counted once, as a duplicate.
//
// A LossRLEInterpreter is not safe for concurrent use.
type LossRLEInterpreter struct {
	sources map[uint32]*lossRLE
	order   []uint32 // SSRCs in first-seen order, for deterministic output
}

// NewLossRLEInterpreter returns an empty interpreter.
func NewLossRLEInterpreter() *LossRLEInterpreter {
	return &LossRLEInterpreter{sources: make(map[uint32]*lossRLE)}
}

// Clear discards all state, leaving the interpreter ready for a new session.
func (i *LossRLEInterpreter) Clear() {
	i.sources = make(map[uint32]*lossRLE)
	i.order = nil
}

// Interpret interprets every Loss RLE and Duplicate RLE report block in report,
// updates the interpreter's state and returns the interpreted windows.
//
// Blocks of other types and packets without RLE blocks produce no windows and
// no error. A block that cannot be interpreted is left out and reported as an
// error; the remaining blocks of the packet are still interpreted. When
// several blocks fail, the returned error joins them in report order.
//
// An empty range (begin_seq equal to end_seq), a range of 65534 or more
// sequence numbers, an invalid chunk, and chunks that do not describe the
// whole thinned trace are all errors. A trailing terminating null chunk is
// accepted; a chunk after it is an error.
func (i *LossRLEInterpreter) Interpret(report *ExtendedReport) ([]RLEWindow, error) {
	if report == nil {
		return nil, errNilExtendedReport
	}
	if i.sources == nil {
		i.sources = make(map[uint32]*lossRLE)
	}

	var windows []RLEWindow
	var errs []error
	for _, block := range report.Reports {
		var (
			rleBlock  *rleReportBlock
			duplicate bool
		)
		switch typedBlock := block.(type) {
		case *LossRLEReportBlock:
			if typedBlock == nil {
				errs = append(errs, errNilRLEBlock)

				continue
			}
			rleBlock = (*rleReportBlock)(typedBlock)
		case *DuplicateRLEReportBlock:
			if typedBlock == nil {
				errs = append(errs, errNilRLEBlock)

				continue
			}
			rleBlock = (*rleReportBlock)(typedBlock)
			duplicate = true
		default:
			continue
		}

		window, err := i.interpretWindow(rleBlock, report.SenderSSRC, duplicate)
		if err != nil {
			errs = append(errs, err)

			continue
		}
		windows = append(windows, window)
	}

	return windows, errors.Join(errs...)
}

// InterpretPacket interprets p if it is an ExtendedReport or a CompoundPacket
// containing ExtendedReports. Other packet types are ignored.
func (i *LossRLEInterpreter) InterpretPacket(p Packet) ([]RLEWindow, error) {
	switch pkt := p.(type) {
	case *ExtendedReport:
		return i.Interpret(pkt)
	case *CompoundPacket:
		if pkt == nil {
			return nil, nil
		}

		return i.interpretPackets(*pkt)
	default:
		return nil, nil
	}
}

// InterpretPackets interprets every ExtendedReport in packets, in order. It is
// convenient for the result of Unmarshal, which returns a slice.
func (i *LossRLEInterpreter) InterpretPackets(packets []Packet) ([]RLEWindow, error) {
	return i.interpretPackets(packets)
}

func (i *LossRLEInterpreter) interpretPackets(packets []Packet) ([]RLEWindow, error) {
	var windows []RLEWindow
	var errs []error
	for _, p := range packets {
		x, ok := p.(*ExtendedReport)
		if !ok {
			continue
		}
		interpreted, err := i.Interpret(x)
		windows = append(windows, interpreted...)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return windows, errors.Join(errs...)
}

func (i *LossRLEInterpreter) interpretWindow(block *rleReportBlock, senderSSRC uint32, duplicate bool) (RLEWindow, error) {
	window, trace, err := i.expand(block, senderSSRC, duplicate)
	if err != nil {
		return RLEWindow{}, err
	}

	source := i.source(block.SSRC)
	if !source.refSet {
		source.ref = window.Begin
		source.refSet = true
	}
	source.windows = append(source.windows, window)
	if source.positions == nil {
		source.positions = make(map[uint64]rlePosition)
	}

	step := uint64(1) << block.T
	first := firstThinned(window.Begin, step)
	for index, state := range trace {
		mergePosition(source.positions, first+uint64(index)*step, state, duplicate)
	}
	if window.End > source.ref {
		source.ref = window.End - 1
	}

	return window, nil
}

// mergePosition folds one trace entry into the accumulated state.
func mergePosition(positions map[uint64]rlePosition, position uint64, state rlePosition, duplicate bool) {
	entry := positions[position]
	switch {
	case duplicate:
		if state.duplicate {
			entry.duplicate = true
			positions[position] = entry
		}
	case state.receipt == RLEStatusReceived:
		// Receipt is monotonic; see LossRLEInterpreter's documentation.
		entry.receipt = RLEStatusReceived
		positions[position] = entry
	case state.receipt == RLEStatusLost && entry.receipt == RLEStatusUnknown:
		entry.receipt = RLEStatusLost
		positions[position] = entry
	}
}

// expand validates block and expands its chunks into a trace with one entry per
// sequence number that the block reports on: window.Reported entries, the
// thinned sequence numbers in order. Positions the block does not describe keep
// the zero value.
//
//nolint:cyclop,gocognit
func (i *LossRLEInterpreter) expand(
	block *rleReportBlock, senderSSRC uint32, duplicate bool,
) (RLEWindow, []rlePosition, error) {
	if block.T > 15 {
		return RLEWindow{}, nil, fmt.Errorf("%w: thinning %d is greater than 15", errRLEInvalidChunk, block.T)
	}

	length := (uint64(block.EndSeq) - uint64(block.BeginSeq)) & 0xFFFF
	switch {
	case length == 0:
		return RLEWindow{}, nil, fmt.Errorf("%w: begin_seq %d equals end_seq", errRLEEmptyRange, block.BeginSeq)
	case length >= 0xFFFE:
		return RLEWindow{}, nil, fmt.Errorf(
			"%w: %d sequence numbers from %d to %d", errRLERangeTooLong, length, block.BeginSeq, block.EndSeq)
	}

	reference := uint64(rleInitialSeq)
	if source, ok := i.sources[block.SSRC]; ok && source.refSet {
		reference = source.ref
	}
	begin := extendedSeq(block.BeginSeq, reference)
	// A valid block covers fewer than 65534 sequence numbers, so it cannot wrap
	// more than once and the end follows from the begin directly.
	end := begin + length

	step := uint64(1) << block.T
	first := firstThinned(begin, step)
	reported := uint64(0)
	if first < end {
		reported = (end-first-1)/step + 1
	}

	window := RLEWindow{
		SSRC:        block.SSRC,
		SenderSSRC:  senderSSRC,
		IsDuplicate: duplicate,
		Thinning:    block.T,
		BeginSeq:    block.BeginSeq,
		EndSeq:      block.EndSeq,
		Begin:       begin,
		End:         end,
		Reported:    reported,
	}
	trace := make([]rlePosition, reported)

	// consumed counts trace positions, not sequence numbers: each run or vector
	// position describes the next thinned sequence number.
	consumed := uint64(0)
	terminated := false
	for _, chunk := range block.Chunks {
		if terminated {
			return RLEWindow{}, nil, fmt.Errorf("%w: chunk 0x%04X after a terminating null chunk",
				errRLEInvalidChunk, uint16(chunk))
		}

		switch chunk.Type() {
		case RunLengthChunkType:
			runType, err := chunk.RunType()
			if err != nil {
				return RLEWindow{}, nil, err
			}
			runLength := uint64(chunk.Value())
			if runLength == 0 {
				return RLEWindow{}, nil, fmt.Errorf("%w: run length chunk 0x%04X has length zero",
					errRLEInvalidChunk, uint16(chunk))
			}
			if consumed+runLength > reported {
				return RLEWindow{}, nil, fmt.Errorf(
					"%w: run of %d exceeds the %d remaining trace positions",
					errRLETraceOverflow, runLength, reported-consumed)
			}
			var state rlePosition
			switch {
			case duplicate && runType == 0:
				state = rlePosition{duplicate: true}
			case duplicate:
				// A one in a Duplicate RLE trace means no duplicate was seen,
				// not that the packet was received: a lost packet is also a
				// one. Record nothing.
			case runType == 0:
				state = rlePosition{receipt: RLEStatusLost}
			default:
				state = rlePosition{receipt: RLEStatusReceived}
			}
			for offset := range runLength {
				trace[consumed+offset] = state
			}
			consumed += runLength
		case BitVectorChunkType:
			if consumed >= reported {
				return RLEWindow{}, nil, fmt.Errorf("%w: bit vector chunk 0x%04X beyond the end of the trace",
					errRLETraceOverflow, uint16(chunk))
			}
			// The 15 bits describe the next 15 trace positions. A final vector
			// may extend past the end of the trace; RFC 3611 requires those
			// bits to be zero and to be ignored, so they are not looked at.
			bits := chunk.Value()
			available := reported - consumed
			for bit := range min(uint64(15), available) {
				switch {
				case duplicate && (bits>>(14-bit))&0x01 == 0:
					trace[consumed+bit] = rlePosition{duplicate: true}
				case duplicate:
					// A one says nothing about receipt; see above.
				case (bits>>(14-bit))&0x01 == 1:
					trace[consumed+bit] = rlePosition{receipt: RLEStatusReceived}
				default:
					trace[consumed+bit] = rlePosition{receipt: RLEStatusLost}
				}
			}
			// The vector may run past the end of the trace; the extra bits were
			// ignored above and the trace is complete.
			consumed += min(uint64(15), available)
		case TerminatingNullChunkType:
			terminated = true
		default:
			return RLEWindow{}, nil, fmt.Errorf("%w: chunk 0x%04X", errRLEInvalidChunk, uint16(chunk))
		}
	}

	if consumed < reported {
		return RLEWindow{}, nil, fmt.Errorf("%w: chunks describe %d of %d sequence numbers",
			errRLEIncompleteTrace, consumed, reported)
	}

	for _, state := range trace {
		switch {
		case state.duplicate:
			window.Duplicates++
		case state.receipt == RLEStatusReceived:
			window.Received++
		case state.receipt == RLEStatusLost:
			window.Lost++
		}
	}
	window.LossRate = ratio(window.Lost, window.Received+window.Lost)

	return window, trace, nil
}

// firstThinned returns the smallest multiple of step at or after begin.
func firstThinned(begin, step uint64) uint64 {
	return (begin + step - 1) / step * step
}

func (i *LossRLEInterpreter) source(ssrc uint32) *lossRLE {
	source, ok := i.sources[ssrc]
	if !ok {
		source = &lossRLE{}
		i.sources[ssrc] = source
		i.order = append(i.order, ssrc)
	}

	return source
}

// Intervals returns the merged intervals for every SSRC interpreted so far.
// SSRCs are ordered by first appearance in an interpreted report; intervals
// within an SSRC are ordered by Start.
func (i *LossRLEInterpreter) Intervals() []RLEStream {
	streams := make([]RLEStream, 0, len(i.order))
	for _, ssrc := range i.order {
		streams = append(streams, i.sources[ssrc].stream(ssrc))
	}

	return streams
}

// IntervalsFor returns the merged intervals for one SSRC. The second return
// value is false if the SSRC was never interpreted.
func (i *LossRLEInterpreter) IntervalsFor(ssrc uint32) (RLEStream, bool) {
	source, ok := i.sources[ssrc]
	if !ok {
		return RLEStream{}, false
	}

	return source.stream(ssrc), true
}

// mergePositions turns sorted positions into maximal intervals, dropping
// positions with no status and splitting where a gap or a status change occurs.
func mergePositions(positions []uint64, states map[uint64]rlePosition) []RLEInterval {
	var (
		intervals []RLEInterval
		current   RLEInterval
	)
	for _, position := range positions {
		status := states[position].status()
		if status == RLEStatusUnknown {
			continue
		}
		if current.Len() == 0 || status != current.Status || position != current.End {
			if current.Len() != 0 {
				intervals = append(intervals, current)
			}
			current = RLEInterval{Status: status, Start: position, End: position + 1}

			continue
		}
		current.End = position + 1
	}
	if current.Len() != 0 {
		intervals = append(intervals, current)
	}

	return intervals
}

func (s *lossRLE) stream(ssrc uint32) RLEStream {
	stream := RLEStream{
		SSRC:    ssrc,
		Windows: append([]RLEWindow(nil), s.windows...),
	}
	if len(s.positions) == 0 {
		return stream
	}

	positions := make([]uint64, 0, len(s.positions))
	for position := range s.positions {
		positions = append(positions, position)
	}
	slices.Sort(positions)
	stream.Intervals = mergePositions(positions, s.positions)

	for _, interval := range stream.Intervals {
		switch interval.Status {
		case RLEStatusReceived:
			stream.Received += interval.Len()
		case RLEStatusLost:
			stream.Lost += interval.Len()
		case RLEStatusDuplicate:
			stream.Duplicates += interval.Len()
		case RLEStatusUnknown:
		}
	}

	return stream
}
