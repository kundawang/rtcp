// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run builds a run length chunk of length packets of status runType.
func run(runType uint, length uint16) Chunk {
	return Chunk(uint16(runType&0x01)<<14 | length) //nolint:gosec // G115 test values
}

// vector builds a bit vector chunk from a trace string, most significant bit
// first. The string may be shorter than 15 bits; the remaining bits are zero,
// as RFC 3611 requires for the part of a vector beyond the end of the trace.
func vector(trace string) Chunk {
	if len(trace) > 15 {
		// A test fixture error, not a runtime condition.
		return Chunk(0xFFFF)
	}
	var bits uint16
	for _, bit := range trace {
		bits <<= 1
		if bit == '1' {
			bits |= 1
		}
	}
	for range 15 - len(trace) {
		bits <<= 1
	}

	return Chunk(0x8000 | bits)
}

// lossReport builds a Loss RLE report block for one SSRC.
func lossReport(ssrc uint32, begin, end uint16, thinning uint8, chunks ...Chunk) *LossRLEReportBlock {
	return &LossRLEReportBlock{
		T:        thinning,
		SSRC:     ssrc,
		BeginSeq: begin,
		EndSeq:   end,
		Chunks:   chunks,
	}
}

func duplicateReport(ssrc uint32, begin, end uint16, thinning uint8, chunks ...Chunk) *DuplicateRLEReportBlock {
	return &DuplicateRLEReportBlock{
		T:        thinning,
		SSRC:     ssrc,
		BeginSeq: begin,
		EndSeq:   end,
		Chunks:   chunks,
	}
}

func TestLossRLEWrapAroundInterval(t *testing.T) {
	// 12 sequence numbers, 65530..65535 then 0..5, with 65532 and 65533 lost:
	//   1 1 0 0 1 1 1 1 1 1 1 1
	// Encoded as a run of two receipts, a run of two losses, and one bit
	// vector for the remaining eight receipts (plus seven ignored zero bits).
	report := lossReport(0xAABBCCDD, 65530, 6, 0,
		run(1, 2), run(0, 2), vector("11111111"), Chunk(0))

	interpreter := NewLossRLEInterpreter()
	windows, err := interpreter.Interpret(&ExtendedReport{
		SenderSSRC: 0x01020304,
		Reports:    []ReportBlock{report},
	})
	require.NoError(t, err)
	require.Len(t, windows, 1)

	window := windows[0]
	assert.Equal(t, uint16(65530), window.BeginSeq)
	assert.Equal(t, uint16(6), window.EndSeq)
	assert.Equal(t, uint64(12), window.Reported)
	assert.Equal(t, uint64(10), window.Received)
	assert.Equal(t, uint64(2), window.Lost)
	assert.InDelta(t, 1.0/6.0, window.LossRate, 1e-9)
	// The window straddles the wrap, so its extended end is 6 positions past
	// 65536, not 6 behind 65530.
	assert.Equal(t, window.Begin+12, window.End)

	streams := interpreter.Intervals()
	require.Len(t, streams, 1)
	stream := streams[0]
	assert.Equal(t, uint32(0xAABBCCDD), stream.SSRC)
	assert.Equal(t, uint64(10), stream.Received)
	assert.Equal(t, uint64(2), stream.Lost)
	assert.InDelta(t, 1.0/6.0, stream.LossRate(), 1e-9)

	require.Len(t, stream.Intervals, 3)
	assert.Equal(t, RLEStatusReceived, stream.Intervals[0].Status)
	assert.Equal(t, uint16(65530), stream.Intervals[0].SeqStart())
	assert.Equal(t, uint16(65532), stream.Intervals[0].SeqEnd())
	assert.Equal(t, uint64(2), stream.Intervals[0].Len())

	assert.Equal(t, RLEStatusLost, stream.Intervals[1].Status)
	assert.Equal(t, uint16(65532), stream.Intervals[1].SeqStart())
	assert.Equal(t, uint16(65534), stream.Intervals[1].SeqEnd())
	assert.Equal(t, uint64(2), stream.Intervals[1].Len())

	// One interval spans the wraparound: 65534, 65535, 0, 1, 2, 3, 4, 5.
	assert.Equal(t, RLEStatusReceived, stream.Intervals[2].Status)
	assert.Equal(t, uint16(65534), stream.Intervals[2].SeqStart())
	assert.Equal(t, uint16(6), stream.Intervals[2].SeqEnd())
	assert.Equal(t, uint64(8), stream.Intervals[2].Len())
	assert.Equal(t, stream.Intervals[2].Start, stream.Intervals[1].End)
	assert.Equal(t, stream.Intervals[2].Start+8, stream.Intervals[2].End)
}

func TestLossRLECrossWrapReportsMerge(t *testing.T) {
	// Three consecutive reports of one SSRC, each straddling the 16 bit wrap or
	// overlapping the previous one:
	//
	//   report 1: 65530..65535, 0..5   lost 65532, 65533
	//   report 2: 65534..65535, 0..9   lost 65535 and 2       (overlaps report 1)
	//   report 3: 2..16                lost 5 and 6           (inside report 2)
	const ssrc = 0x11223344
	interpreter := NewLossRLEInterpreter()

	_, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(ssrc, 65530, 6, 0, run(1, 2), run(0, 2), vector("11111111"), Chunk(0)),
		},
	})
	require.NoError(t, err)

	// 12 packets: 65534, 65535, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
	// losses at 65535 and 2.
	_, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(ssrc, 65534, 10, 0, vector("101101111111"), Chunk(0)),
		},
	})
	require.NoError(t, err)

	// 14 packets 2..15 with losses at 5 and 6:
	//   1 1 1 0 0 1 1 1 1 1 1 1 1 1
	_, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(ssrc, 2, 16, 0, vector("11100111111111"), Chunk(0)),
		},
	})
	require.NoError(t, err)

	streams := interpreter.Intervals()
	require.Len(t, streams, 1)
	stream := streams[0]
	require.Len(t, stream.Windows, 3)

	// Final status per sequence number, union of overlapping windows:
	// Every window contributes to one coordinate space. The windows overlap,
	// so later windows repeat much of what earlier ones said; the only
	// sequence numbers that stay lost are the two report 1 found, because
	// every later report says the others were received.
	lostSeqs := sequenceNumbers(stream.LossIntervals())
	assert.ElementsMatch(t, []uint16{65532, 65533}, lostSeqs)
	assert.Equal(t, uint64(len(lostSeqs)), stream.Lost)
	assert.Equal(t, stream.Received+stream.Lost, stream.Observed(),
		"a sequence number reported by several windows must be counted once")
	assert.InDelta(t, float64(stream.Lost)/float64(stream.Observed()), stream.LossRate(), 1e-9)

	// Windows keep the per-report view, including their own loss rates.
	require.Len(t, stream.Windows, 3)
	assert.InDelta(t, 2.0/12.0, stream.Windows[0].LossRate, 1e-9)
	assert.InDelta(t, 2.0/12.0, stream.Windows[1].LossRate, 1e-9)
	assert.InDelta(t, 2.0/14.0, stream.Windows[2].LossRate, 1e-9)
	assert.Equal(t, stream.Windows[0].Begin+4, stream.Windows[1].Begin,
		"report 2 overlaps report 1 (65534 is 4 past 65530), it does not restart the sequence space")
	assert.Greater(t, stream.Windows[2].Begin, stream.Windows[1].Begin,
		"a report inside the already seen window stays in the same sequence space")
}

func TestLossRLEIntervalsAreMergedAndSorted(t *testing.T) {
	const ssrc = 0xDEADBEEF
	interpreter := NewLossRLEInterpreter()

	// Interpret the newer window first, then the older overlapping one, to
	// exercise out-of-order arrival rather than monotonic arrival.
	// 10..14: losses at 12 and 13  -> 1 1 0 0 1
	_, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{lossReport(ssrc, 10, 15, 0, vector("11001"), Chunk(0))},
	})
	require.NoError(t, err)

	// 6..9: all received.
	_, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{lossReport(ssrc, 6, 10, 0, run(1, 4), Chunk(0))},
	})
	require.NoError(t, err)

	stream, ok := interpreter.IntervalsFor(ssrc)
	require.True(t, ok)
	require.Len(t, stream.Intervals, 3)

	// Extended sequence numbers are interpreter-internal; the 16 bit values
	// and the relative positions are what callers depend on.
	base := stream.Intervals[0].Start
	assert.Equal(t, RLEStatusReceived, stream.Intervals[0].Status)
	assert.Equal(t, uint16(6), stream.Intervals[0].SeqStart())
	assert.Equal(t, uint16(12), stream.Intervals[0].SeqEnd())
	assert.Equal(t, uint64(6), stream.Intervals[0].Len())

	assert.Equal(t, RLEStatusLost, stream.Intervals[1].Status)
	assert.Equal(t, uint16(12), stream.Intervals[1].SeqStart())
	assert.Equal(t, uint16(14), stream.Intervals[1].SeqEnd())
	assert.Equal(t, base+6, stream.Intervals[1].Start)

	assert.Equal(t, RLEStatusReceived, stream.Intervals[2].Status)
	assert.Equal(t, uint16(14), stream.Intervals[2].SeqStart())
	assert.Equal(t, uint16(15), stream.Intervals[2].SeqEnd())
	assert.Equal(t, base+8, stream.Intervals[2].Start)

	// The interval list is ordered and does not overlap.
	for index := 1; index < len(stream.Intervals); index++ {
		assert.LessOrEqual(t, stream.Intervals[index-1].End, stream.Intervals[index].Start)
	}
}

func TestLossRLESourcesAreIndependent(t *testing.T) {
	interpreter := NewLossRLEInterpreter()

	_, err := interpreter.Interpret(&ExtendedReport{
		SenderSSRC: 0x01,
		Reports: []ReportBlock{
			lossReport(0xAAAA0001, 65530, 6, 0, run(1, 2), run(0, 2), vector("11111111"), Chunk(0)),
			lossReport(0xAAAA0002, 0, 12, 0, run(0, 4), vector("11111111"), Chunk(0)),
		},
	})
	require.NoError(t, err)

	streams := interpreter.Intervals()
	require.Len(t, streams, 2)
	assert.Equal(t, uint32(0xAAAA0001), streams[0].SSRC)
	assert.Equal(t, uint32(0xAAAA0002), streams[1].SSRC)
	// Both sources may start anywhere in the 16 bit space: a wrap on one does
	// not shift the other.
	assert.Equal(t, uint64(10), streams[0].Received)
	assert.Equal(t, uint64(2), streams[0].Lost)
	assert.Equal(t, uint64(8), streams[1].Received)
	assert.Equal(t, uint64(4), streams[1].Lost)
	assert.Equal(t, uint32(0x01), streams[0].Windows[0].SenderSSRC)

	stream, ok := interpreter.IntervalsFor(0xAAAA0002)
	require.True(t, ok)
	assert.Equal(t, uint64(4), stream.Lost)
	_, ok = interpreter.IntervalsFor(0xBBBB0003)
	assert.False(t, ok)
}

func TestLossRLEDuplicateReport(t *testing.T) {
	const ssrc = 0x0BADF00D
	interpreter := NewLossRLEInterpreter()

	// Loss window 100..104 reports 102 lost:
	//   1 1 0 1 1
	_, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{lossReport(ssrc, 100, 105, 0, vector("11011"), Chunk(0))},
	})
	require.NoError(t, err)

	// Duplicate window 100..104: duplicates at 101 and 103. In a duplicate
	// trace a zero means "duplicate", not "lost", and a one means only that no
	// duplicate was seen, which says nothing about receipt.
	//   1 0 1 0 1
	_, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{duplicateReport(ssrc, 100, 105, 0, vector("10101"), Chunk(0))},
	})
	require.NoError(t, err)

	streams := interpreter.Intervals()
	require.Len(t, streams, 1)
	stream := streams[0]
	require.Len(t, stream.Windows, 2)

	duplicateWindow := stream.Windows[1]
	assert.True(t, duplicateWindow.IsDuplicate)
	assert.Equal(t, uint64(2), duplicateWindow.Duplicates)
	assert.Equal(t, uint64(0), duplicateWindow.Received)
	assert.Equal(t, uint64(0), duplicateWindow.Lost)
	assert.Zero(t, duplicateWindow.LossRate,
		"a duplicate trace carries no receipt information, so no loss rate")

	assert.Equal(t, uint64(2), stream.Duplicates) // 101, 103
	assert.Equal(t, uint64(1), stream.Lost)       // 102
	assert.Equal(t, uint64(2), stream.Received)   // 100, 104 from the loss report
	assert.Equal(t, uint64(5), stream.Observed())
	assert.InDelta(t, 1.0/5.0, stream.LossRate(), 1e-9)

	duplicates := stream.DuplicateIntervals()
	require.Len(t, duplicates, 2)
	assert.Equal(t, uint16(101), duplicates[0].SeqStart())
	assert.Equal(t, uint16(103), duplicates[1].SeqStart())

	// Repeating the same duplicate marker must not count it twice.
	_, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{duplicateReport(ssrc, 100, 105, 0, vector("10101"), Chunk(0))},
	})
	require.NoError(t, err)
	streams = interpreter.Intervals()
	require.Len(t, streams, 1)
	assert.Equal(t, uint64(2), streams[0].Duplicates)
	assert.Equal(t, uint64(5), streams[0].Observed())
}

func TestLossRLEDuplicateTakesPrecedenceOverLoss(t *testing.T) {
	const ssrc = 0x00000001
	interpreter := NewLossRLEInterpreter()

	// A sequence number cannot be both lost and duplicated: a duplicate means a
	// packet was received. The duplicate marker therefore wins over a loss, and
	// it is not retracted by a later loss report.
	_, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(ssrc, 0, 4, 0, run(0, 4), Chunk(0)),
			duplicateReport(ssrc, 1, 2, 0, run(0, 1), Chunk(0)),
		},
	})
	require.NoError(t, err)

	stream, ok := interpreter.IntervalsFor(ssrc)
	require.True(t, ok)
	require.Len(t, stream.Intervals, 3)
	assert.Equal(t, RLEStatusLost, stream.Intervals[0].Status)
	assert.Equal(t, uint64(1), stream.Intervals[0].Len())
	assert.Equal(t, RLEStatusDuplicate, stream.Intervals[1].Status)
	assert.Equal(t, uint16(1), stream.Intervals[1].SeqStart())
	assert.Equal(t, RLEStatusLost, stream.Intervals[2].Status)
	assert.Equal(t, uint64(2), stream.Intervals[2].Len()) // 2 and 3
	assert.Equal(t, uint64(3), stream.Lost)               // 0, 2, 3
	assert.Equal(t, uint64(1), stream.Duplicates)         // 1
	assert.Equal(t, uint64(4), stream.Observed())
}

func TestLossRLEThinning(t *testing.T) {
	// RFC 3611, section 4.1: a trace from 13,821 to 13,865 thinned with T=2
	// reports on the multiples of 4. The trace is
	//   1 1 1 1 1 0 1 1 1 1 0
	// and the block uses one bit vector plus a null chunk.
	interpreter := NewLossRLEInterpreter()
	windows, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(0x1234, 13821, 13866, 2, vector("11111011110"), Chunk(0)),
		},
	})
	require.NoError(t, err)
	require.Len(t, windows, 1)

	window := windows[0]
	assert.Equal(t, uint8(2), window.Thinning)
	assert.Equal(t, uint64(11), window.Reported, "one sequence number in four is reported")
	assert.Equal(t, uint64(9), window.Received)
	assert.Equal(t, uint64(2), window.Lost)
	assert.InDelta(t, 2.0/11.0, window.LossRate, 1e-9)

	stream := interpreter.Intervals()[0]
	// The thinned-out sequence numbers are not reported at all, so they are not
	// intervals.
	assert.Equal(t, uint64(11), stream.Observed())
	lost := stream.LossIntervals()
	require.Len(t, lost, 2)
	assert.Equal(t, uint16(13844), lost[0].SeqStart())
	assert.Equal(t, uint16(13864), lost[1].SeqStart())

	// Without thinning the same range would report 44 or 45 sequence numbers.
	unthinned := NewLossRLEInterpreter()
	unthinnedWindows, err := unthinned.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(0x1234, 13821, 13866, 0, run(1, 45), Chunk(0)),
		},
	})
	require.NoError(t, err)
	require.Len(t, unthinnedWindows, 1)
	assert.Equal(t, uint64(45), unthinnedWindows[0].Reported)
}

func TestLossRLEBitVectorBeyondTrace(t *testing.T) {
	// RFC 3611 allows a final bit vector to run past the end of the trace,
	// provided the extra bits are zero; they must be ignored. The vector holds
	// five ones and ten zeros, which a decoder that does not clamp would read
	// as ten losses.
	interpreter := NewLossRLEInterpreter()
	windows, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(0x1, 0, 5, 0, vector("11111"), Chunk(0)),
		},
	})
	require.NoError(t, err)
	require.Len(t, windows, 1)
	assert.Equal(t, uint64(5), windows[0].Reported)
	assert.Equal(t, uint64(5), windows[0].Received)
	assert.Equal(t, uint64(0), windows[0].Lost)

	stream := interpreter.Intervals()[0]
	require.Len(t, stream.Intervals, 1)
	assert.Equal(t, uint64(5), stream.Intervals[0].Len())
}

func TestLossRLEEmptyReport(t *testing.T) {
	// An ExtendedReport with no report blocks is valid and carries no loss
	// information.
	interpreter := NewLossRLEInterpreter()
	windows, err := interpreter.Interpret(&ExtendedReport{SenderSSRC: 1})
	require.NoError(t, err)
	assert.Empty(t, windows)
	assert.Empty(t, interpreter.Intervals())

	// So is a packet with only report blocks that are not RLE.
	windows, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			&ReceiverReferenceTimeReportBlock{NTPTimestamp: 1},
			&VoIPMetricsReportBlock{SSRC: 2},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, windows)
	assert.Empty(t, interpreter.Intervals())

	// A nil packet is an error, not a panic.
	_, err = interpreter.Interpret(nil)
	require.ErrorIs(t, err, errNilExtendedReport)

	// A typed nil report block is an error for that block only.
	windows, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			(*LossRLEReportBlock)(nil),
			lossReport(0x1, 0, 1, 0, run(1, 1), Chunk(0)),
		},
	})
	require.ErrorIs(t, err, errNilRLEBlock)
	assert.Len(t, windows, 1)
}

func TestLossRLEInvalidChunks(t *testing.T) {
	tests := []struct {
		name    string
		block   *LossRLEReportBlock
		wantErr error
	}{
		{
			name:    "empty range",
			block:   lossReport(1, 10, 10, 0, run(1, 1), Chunk(0)),
			wantErr: errRLEEmptyRange,
		},
		{
			name:    "range too long",
			block:   lossReport(1, 10, 8, 0, run(1, 1), Chunk(0)), // 65534 positions
			wantErr: errRLERangeTooLong,
		},
		{
			name:    "zero length run",
			block:   lossReport(1, 0, 4, 0, run(1, 0)),
			wantErr: errRLEInvalidChunk,
		},
		{
			name:    "chunks too short",
			block:   lossReport(1, 0, 4, 0, run(1, 3), Chunk(0)),
			wantErr: errRLEIncompleteTrace,
		},
		{
			name:    "no chunks",
			block:   lossReport(1, 0, 4, 0),
			wantErr: errRLEIncompleteTrace,
		},
		{
			name:    "run too long",
			block:   lossReport(1, 0, 4, 0, run(1, 5), Chunk(0)),
			wantErr: errRLETraceOverflow,
		},
		{
			name:    "chunk after terminator",
			block:   lossReport(1, 0, 2, 0, run(1, 2), Chunk(0), run(1, 1)),
			wantErr: errRLEInvalidChunk,
		},
		{
			name: "thinning out of range",
			// T > 15 cannot be represented by unpackBlockHeader, but a locally
			// constructed block can carry it.
			block:   lossReport(1, 0, 1, 16, run(1, 1), Chunk(0)),
			wantErr: errRLEInvalidChunk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interpreter := NewLossRLEInterpreter()
			windows, err := interpreter.Interpret(&ExtendedReport{
				Reports: []ReportBlock{test.block},
			})
			require.ErrorIs(t, err, test.wantErr)
			assert.Empty(t, windows)
			assert.Empty(t, interpreter.Intervals(),
				"a rejected report must not leave state behind")
		})
	}
}

func TestLossRLEOneBadBlockDoesNotDiscardOthers(t *testing.T) {
	interpreter := NewLossRLEInterpreter()
	windows, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(1, 0, 10, 0, run(1, 1)), // incomplete trace
			lossReport(2, 0, 2, 0, run(0, 2), Chunk(0)),
		},
	})
	require.ErrorIs(t, err, errRLEIncompleteTrace)
	require.Len(t, windows, 1)
	assert.Equal(t, uint32(2), windows[0].SSRC)

	streams := interpreter.Intervals()
	require.Len(t, streams, 1)
	assert.Equal(t, uint32(2), streams[0].SSRC)
	assert.Equal(t, uint64(2), streams[0].Lost)
}

func TestLossRLEReportOrderAndContradiction(t *testing.T) {
	const ssrc = 0xCAFEBABE

	t.Run("a contradiction resolves to receipt", func(t *testing.T) {
		interpreter := NewLossRLEInterpreter()
		_, err := interpreter.Interpret(&ExtendedReport{
			Reports: []ReportBlock{lossReport(ssrc, 0, 4, 0, run(1, 4), Chunk(0))},
		})
		require.NoError(t, err)
		_, err = interpreter.Interpret(&ExtendedReport{
			Reports: []ReportBlock{lossReport(ssrc, 0, 4, 0, run(0, 4), Chunk(0))},
		})
		require.NoError(t, err)

		// A receipt is evidence that cannot be undone by a report of absence.
		stream, ok := interpreter.IntervalsFor(ssrc)
		require.True(t, ok)
		assert.Equal(t, uint64(0), stream.Lost)
		assert.Equal(t, uint64(4), stream.Received)
	})

	t.Run("later receipt wins", func(t *testing.T) {
		// A sequence number reported lost may be reported received later, once
		// the late packet arrives (RFC 3611, section 4.1).
		interpreter := NewLossRLEInterpreter()
		_, err := interpreter.Interpret(&ExtendedReport{
			Reports: []ReportBlock{lossReport(ssrc, 0, 4, 0, run(0, 4), Chunk(0))},
		})
		require.NoError(t, err)
		_, err = interpreter.Interpret(&ExtendedReport{
			Reports: []ReportBlock{lossReport(ssrc, 0, 4, 0, run(1, 4), Chunk(0))},
		})
		require.NoError(t, err)

		stream, ok := interpreter.IntervalsFor(ssrc)
		require.True(t, ok)
		assert.Equal(t, uint64(0), stream.Lost)
		assert.Equal(t, uint64(4), stream.Received)
	})

	t.Run("out of order reports are placed by sequence number", func(t *testing.T) {
		// The newer window arrives first. The older window overlaps it. The
		// result must be the same as for in-order arrival: the conflict is
		// resolved by interpretation order, not by arrival, but placement is by
		// sequence number so the intervals do not jump.
		newerFirst := NewLossRLEInterpreter()
		// 65534..65535, 0..9: losses at 65535 and 2.
		_, err := newerFirst.Interpret(&ExtendedReport{
			Reports: []ReportBlock{lossReport(ssrc, 65534, 10, 0, vector("101101111111"), Chunk(0))},
		})
		require.NoError(t, err)
		// 65530..65535, 0..5: losses at 65532 and 65533.
		_, err = newerFirst.Interpret(&ExtendedReport{
			Reports: []ReportBlock{lossReport(ssrc, 65530, 6, 0, run(1, 2), run(0, 2), vector("11111111"), Chunk(0))},
		})
		require.NoError(t, err)

		stream, ok := newerFirst.IntervalsFor(ssrc)
		require.True(t, ok)
		// Both reports are reflected even though the older one arrived last,
		// and the older one is placed before the wraparound rather than after
		// the newer window. Receipt is monotonic, so the result is the same as
		// for in-order arrival.
		// Both windows are placed in one coordinate space even though the older
		// one arrived last, and sequence 2 is received in the window that
		// arrived last, so receipt is monotonic and it stays received.
		assert.ElementsMatch(t, []uint16{65532, 65533},
			sequenceNumbers(stream.LossIntervals()))
		for index := 1; index < len(stream.Intervals); index++ {
			assert.LessOrEqual(t, stream.Intervals[index-1].End, stream.Intervals[index].Start)
		}
	})
}

func TestLossRLEAcrossEpochBoundary(t *testing.T) {
	// Reports separated by a genuine wraparound must land in different epochs,
	// not be folded back onto the first window. Start near the end of the 16
	// bit space, wrap, and keep going past one full sequence space.
	const ssrc = 0x0F0F0F0F
	interpreter := NewLossRLEInterpreter()

	// Window 65500..65535, 0..9: 46 packets, all received. Encoded as three
	// bit vectors and a null chunk.
	_, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(ssrc, 65500, 10, 0,
				vector("111111111111111"), vector("111111111111111"),
				vector("111111111111111"), vector("1111111"), Chunk(0)),
		},
	})
	require.NoError(t, err)

	// A later window that starts one full sequence space further on is
	// ambiguous; what must hold is that the interpreter does not create a
	// reverse or overlapping interval for the same epoch.
	_, err = interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{lossReport(ssrc, 12, 16, 0, run(0, 4), Chunk(0))},
	})
	require.NoError(t, err)

	stream, ok := interpreter.IntervalsFor(ssrc)
	require.True(t, ok)
	for index := 1; index < len(stream.Intervals); index++ {
		assert.LessOrEqual(t, stream.Intervals[index-1].End, stream.Intervals[index].Start)
	}
	// The 0..9 part of the wrapped window and the 12..15 loss are in the same
	// epoch, so the difference in extended coordinates must be small.
	last := stream.Intervals[len(stream.Intervals)-1]
	assert.Equal(t, RLEStatusLost, last.Status)
	assert.Equal(t, uint64(4), last.Len())
	assert.Less(t, last.Start-stream.Windows[0].Begin, uint64(64),
		"the sequence numbers after the wrap must not be placed a whole epoch away")
}

func TestLossRLEEncodeDecodeRoundTrip(t *testing.T) {
	// Build chunks by hand, put them on the wire, and confirm the interpreter
	// sees the same trace after Unmarshal as it did before Marshal. The window
	// crosses the wraparound so the round trip exercises begin_seq > end_seq.
	report := lossReport(0xAABBCCDD, 65530, 6, 0,
		run(1, 2), run(0, 2), vector("11111111"), Chunk(0))
	packet := &ExtendedReport{
		SenderSSRC: 0x01020304,
		Reports:    []ReportBlock{report},
	}

	raw, err := packet.Marshal()
	require.NoError(t, err)

	decoded, err := Unmarshal(raw)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	decodedReport, ok := decoded[0].(*ExtendedReport)
	require.True(t, ok)
	require.Len(t, decodedReport.Reports, 1)

	decodedBlock, ok := decodedReport.Reports[0].(*LossRLEReportBlock)
	require.True(t, ok)
	assert.Equal(t, uint16(65530), decodedBlock.BeginSeq)
	assert.Equal(t, uint16(6), decodedBlock.EndSeq)
	assert.Equal(t, report.Chunks, decodedBlock.Chunks)

	fromStruct := NewLossRLEInterpreter()
	structWindows, err := fromStruct.Interpret(packet)
	require.NoError(t, err)

	fromWire := NewLossRLEInterpreter()
	wireWindows, err := fromWire.Interpret(decodedReport)
	require.NoError(t, err)

	require.Len(t, structWindows, 1)
	require.Len(t, wireWindows, 1)
	assert.Equal(t, structWindows[0], wireWindows[0])
	assert.Equal(t, fromStruct.Intervals(), fromWire.Intervals())

	// The pre-Marshal header is zero; Marshal fixes it up, which is why the
	// windows must be built from fields rather than from the header.
	assert.Equal(t, BlockTypeType(LossRLEReportBlockType), decodedBlock.BlockType)
	assert.Equal(t, TypeSpecificField(0), decodedBlock.TypeSpecific)
}

func TestLossRLERunAndVectorEquivalence(t *testing.T) {
	// RFC 3611, section 4.1: the choice of run length versus bit vector is not
	// unique. The same trace must interpret identically either way.
	const ssrc = 0x99887766
	// 22 receipts, 2 losses, 18 receipts, 2 losses, 6 receipts over 50 packets.

	fromRuns := NewLossRLEInterpreter()
	_, err := fromRuns.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(ssrc, 1000, 1050, 0,
				run(1, 22), run(0, 2), run(1, 18), run(0, 2), run(1, 6), Chunk(0)),
		},
	})
	require.NoError(t, err)

	fromVectors := NewLossRLEInterpreter()
	_, err = fromVectors.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(ssrc, 1000, 1050, 0,
				vector("111111111111111"), vector("111111100111111"),
				vector("111111111111001"), vector("11111"), Chunk(0)),
		},
	})
	require.NoError(t, err)

	assert.Equal(t, fromRuns.Intervals(), fromVectors.Intervals())
}

func TestLossRLEInterpretPacket(t *testing.T) {
	interpreter := NewLossRLEInterpreter()

	// Non-EXR packets are ignored.
	windows, err := interpreter.InterpretPacket(&PictureLossIndication{MediaSSRC: 1})
	require.NoError(t, err)
	assert.Empty(t, windows)

	// A compound packet is interpreted by walking its members.
	compound := &CompoundPacket{
		&ExtendedReport{
			Reports: []ReportBlock{lossReport(1, 0, 2, 0, run(0, 2), Chunk(0))},
		},
		&PictureLossIndication{MediaSSRC: 3},
	}
	windows, err = interpreter.InterpretPacket(compound)
	require.NoError(t, err)
	require.Len(t, windows, 1)
	assert.Equal(t, uint64(2), windows[0].Lost)

	// A nil compound pointer is a no-op.
	windows, err = interpreter.InterpretPacket((*CompoundPacket)(nil))
	require.NoError(t, err)
	assert.Empty(t, windows)

	// InterpretPackets accepts the output of Unmarshal directly.
	windows, err = interpreter.InterpretPackets([]Packet{
		&ExtendedReport{Reports: []ReportBlock{lossReport(2, 0, 1, 0, run(1, 1), Chunk(0))}},
		&PictureLossIndication{MediaSSRC: 2},
	})
	require.NoError(t, err)
	require.Len(t, windows, 1)
	assert.Equal(t, uint32(2), windows[0].SSRC)
}

func TestLossRLEClear(t *testing.T) {
	interpreter := NewLossRLEInterpreter()
	_, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{lossReport(1, 0, 2, 0, run(0, 2), Chunk(0))},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, interpreter.Intervals())

	interpreter.Clear()
	assert.Empty(t, interpreter.Intervals())
	_, ok := interpreter.IntervalsFor(1)
	assert.False(t, ok)

	// The zero value is usable too.
	var zero LossRLEInterpreter
	_, err = zero.Interpret(&ExtendedReport{
		Reports: []ReportBlock{lossReport(1, 0, 2, 0, run(0, 2), Chunk(0))},
	})
	require.NoError(t, err)
	assert.Len(t, zero.Intervals(), 1)
}

func TestRLEIntervalAndStreamString(t *testing.T) {
	interval := RLEInterval{Status: RLEStatusLost, Start: 65530, End: 65536}
	assert.Equal(t, "lost [65530-65535] (6 packets)", interval.String())
	assert.Equal(t, uint16(65530), interval.SeqStart())
	assert.Equal(t, uint16(0), interval.SeqEnd())
	assert.Equal(t, uint64(6), interval.Len())

	window := RLEWindow{
		SSRC: 0x1, BeginSeq: 65530, EndSeq: 6, Reported: 12,
		Received: 10, Lost: 2, LossRate: 1.0 / 6.0,
	}
	assert.Contains(t, window.String(), "SSRC 0x1 loss window seq 65530-6 T=0")

	stream := RLEStream{SSRC: 0x1, Intervals: []RLEInterval{interval}, Lost: 6}
	assert.Contains(t, stream.String(), "loss_rate=1.000")
}

func TestExtendedSeqTie(t *testing.T) {
	// At exactly 32768 positions the RFC prose chooses the interpretation that
	// requires no rollover, which is the candidate in the reference epoch.
	const reference = uint64(0x10000)
	assert.Equal(t, reference+0x8000, extendedSeq(0x8000, reference))
	assert.Equal(t, reference-0x8000, extendedSeq(0x8000, reference-0x1))
	// Just past the midpoint is closer as a preceding sequence number, so it
	// is placed before the reference epoch.
	assert.Equal(t, reference-0x7FFF, extendedSeq(0x8001, reference))
	assert.Equal(t, reference+0x7FFF, extendedSeq(0x7FFF, reference))
	// A value just below the reference epoch is placed before it.
	assert.Equal(t, reference-1, extendedSeq(0xFFFF, reference))
	// A value just above the reference epoch is placed after it.
	assert.Equal(t, reference+1, extendedSeq(0x1, reference))
}

// sequenceNumbers expands intervals to the 16 bit sequence numbers they cover.
func sequenceNumbers(intervals []RLEInterval) []uint16 {
	var sequence []uint16
	for _, interval := range intervals {
		for extended := interval.Start; extended < interval.End; extended++ {
			sequence = append(sequence, uint16(extended&0xFFFF)) //nolint:gosec // G115
		}
	}

	return sequence
}

func TestLossRLEWindowErrorsAreJoined(t *testing.T) {
	interpreter := NewLossRLEInterpreter()
	_, err := interpreter.Interpret(&ExtendedReport{
		Reports: []ReportBlock{
			lossReport(1, 0, 0, 0, run(1, 1), Chunk(0)),
			lossReport(2, 0, 0xFFFF, 0, run(1, 1), Chunk(0)),
		},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errRLEEmptyRange))
	assert.True(t, errors.Is(err, errRLERangeTooLong))
}

func TestLossRLEInvalidBlockFromWire(t *testing.T) {
	// Unmarshal does not validate chunk layout; the interpreter must, rather
	// than guess. The block claims 12 sequence numbers and carries a single run
	// plus a null chunk.
	raw := []byte{
		0x80, 0xCF, 0x00, 0x05, // XR header, 6 words total
		0x01, 0x02, 0x03, 0x04, // sender SSRC
		0x01, 0x00, 0x00, 0x03, // Loss RLE, block length 4 words
		0xAA, 0xBB, 0xCC, 0xDD, // source SSRC
		0x00, 0x0A, 0x00, 0x16, // begin 10, end 22
		0x40, 0x0C, 0x00, 0x00, // run of 12 receipts, then a null chunk
	}

	packets, err := Unmarshal(raw)
	require.NoError(t, err)
	require.Len(t, packets, 1)

	interpreter := NewLossRLEInterpreter()
	windows, err := interpreter.InterpretPackets(packets)
	require.NoError(t, err)
	require.Len(t, windows, 1)
	assert.Equal(t, uint32(0xAABBCCDD), windows[0].SSRC)
	assert.Equal(t, uint64(12), windows[0].Received)
	assert.Equal(t, uint64(0), windows[0].Lost)

	// Now shorten the run by one: the chunks no longer reach the end of the
	// trace, and the null chunk does not make up the difference. The block is
	// structurally valid RTCP and still decodes; only the trace is incomplete.
	raw[21] = 0x0B
	packets, err = Unmarshal(raw)
	require.NoError(t, err)

	interpreter = NewLossRLEInterpreter()
	windows, err = interpreter.InterpretPackets(packets)
	require.ErrorIs(t, err, errRLEIncompleteTrace)
	assert.Empty(t, windows)
}

func TestLossRLEWindowLossRateList(t *testing.T) {
	const ssrc = 0xABC
	interpreter := NewLossRLEInterpreter()
	for _, begin := range []uint16{0, 10, 20} {
		_, err := interpreter.Interpret(&ExtendedReport{
			Reports: []ReportBlock{
				lossReport(ssrc, begin, begin+10, 0, run(1, 8), run(0, 2), Chunk(0)),
			},
		})
		require.NoError(t, err)
	}

	stream, ok := interpreter.IntervalsFor(ssrc)
	require.True(t, ok)
	assert.InDeltaSlice(t, []float64{0.2, 0.2, 0.2}, stream.WindowLossRate(), 1e-9)
	// Overlapping windows would otherwise leave 30 observed sequence numbers;
	// these windows are disjoint so all 30 remain.
	assert.Equal(t, uint64(30), stream.Observed())
	assert.Equal(t, uint64(6), stream.Lost)
}

func TestLossRLERandomizedBlocksNeverPanic(t *testing.T) {
	// Deterministic pseudo-random blocks: the interpreter must never panic and
	// must always return ordered, non-overlapping intervals, whatever the chunks
	// claim. This is a robustness check for malformed and contradictory input,
	// not a correctness oracle.
	state := uint64(0x9E3779B97F4A7C15)
	next := func() uint16 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17

		return uint16(state) //nolint:gosec // G115 test value
	}

	for iteration := range 2000 {
		begin := next()
		width := next() % 200
		end := begin + width
		chunks := make([]Chunk, next()%8)
		for index := range chunks {
			chunks[index] = Chunk(next())
		}

		interpreter := NewLossRLEInterpreter()
		_, _ = interpreter.Interpret(&ExtendedReport{
			Reports: []ReportBlock{
				lossReport(uint32(next()), begin, end, uint8(next()%16), chunks...),
				duplicateReport(uint32(next()), end, begin, uint8(next()%16), chunks...),
			},
		})

		for _, stream := range interpreter.Intervals() {
			assert.Equal(t, stream.Observed(), stream.Received+stream.Lost+stream.Duplicates,
				"iteration %d", iteration)
			for index := 1; index < len(stream.Intervals); index++ {
				// Intervals may touch, which is how a status change is
				// represented, but they may never overlap. Two adjacent
				// intervals of the same status are expected for a thinned
				// trace: the sequence numbers between them were not reported.
				assert.LessOrEqual(t, stream.Intervals[index-1].End, stream.Intervals[index].Start,
					"iteration %d: intervals must not overlap", iteration)
			}
			for _, interval := range stream.Intervals {
				assert.Greater(t, interval.End, interval.Start, "iteration %d", iteration)
				assert.Less(t, interval.Len(), uint64(0xFFFE), "iteration %d", iteration)
			}
		}
	}
}
