// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// manualClock is a controllable clock for DLRRReportBuilder tests. Tests use
// wall-clock times because a manually advanced clock has no monotonic reading;
// the builder only ever subtracts two samples taken from the same clock.
type manualClock struct {
	now time.Time
}

func newManualClock(t *testing.T) *manualClock {
	t.Helper()

	return &manualClock{now: time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)}
}

func (c *manualClock) Now() time.Time {
	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// dlrrUnits is the expected DLRR field for a local delay.
func dlrrUnits(d time.Duration) uint32 {
	return uint32((uint64(d)*dlrrUnitsPerSecond + uint64(time.Second)/2) / uint64(time.Second)) //nolint:gosec // G115
}

// wantLastRR is the middle 32 bits of an NTP timestamp, as the builder must
// report them.
func wantLastRR(ntpTimestamp uint64) uint32 {
	return uint32(ntpTimestamp >> 16) //nolint:gosec // G115
}

func TestDLRRReportBuilderTwoReporters(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	const (
		reporterA = 0xAAAAAAAA
		reporterB = 0xBBBBBBBB
		ntpA      = uint64(0x0102030405060708)
		ntpB      = uint64(0x1112131415161718)
	)

	assert.True(t, builder.Record(reporterA, ntpA))
	clock.Advance(500 * time.Millisecond)
	assert.True(t, builder.Record(reporterB, ntpB))
	clock.Advance(1500 * time.Millisecond)

	block := builder.Build(false)
	require.NotNil(t, block)
	// Build returns a block ready to be marshaled, header included.
	block.setupBlockHeader()
	assert.Equal(t, BlockTypeType(DLRRReportBlockType), block.XRHeader.BlockType)
	require.Len(t, block.Reports, 2)

	// Reporters are always emitted in ascending SSRC order, regardless of the
	// order in which their reports arrived.
	assert.Equal(t, []DLRRReport{
		{
			SSRC:   reporterA,
			LastRR: wantLastRR(ntpA),
			DLRR:   dlrrUnits(2 * time.Second),
		},
		{
			SSRC:   reporterB,
			LastRR: wantLastRR(ntpB),
			DLRR:   dlrrUnits(1500 * time.Millisecond),
		},
	}, block.Reports)

	assert.Equal(t, []uint32{reporterA, reporterB}, block.DestinationSSRC())
}

func TestDLRRReportBuilderRetainAndConsume(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	const (
		reporter  = 0x01020304
		ntp       = uint64(0xE020A2A952A53FC0)
		retention = 100 * time.Millisecond
	)

	require.True(t, builder.Record(reporter, ntp))

	first := builder.Build(false)
	require.NotNil(t, first)
	require.Len(t, first.Reports, 1)
	assert.Equal(t, dlrrUnits(0), first.Reports[0].DLRR)

	// Retaining the state means a later reply keeps reporting the same RRT, with
	// a delay that grows in step with the local clock.
	clock.Advance(retention)
	second := builder.Build(false)
	require.NotNil(t, second)
	require.Len(t, second.Reports, 1)
	assert.Equal(t, first.Reports[0].LastRR, second.Reports[0].LastRR)
	assert.Equal(t, dlrrUnits(retention), second.Reports[0].DLRR)

	// Consuming the state answers once; afterwards there is nothing to report.
	clock.Advance(retention)
	consumed := builder.Build(true)
	require.NotNil(t, consumed)
	require.Len(t, consumed.Reports, 1)
	assert.Equal(t, dlrrUnits(2*retention), consumed.Reports[0].DLRR)

	assert.Nil(t, builder.Build(false))
	assert.Nil(t, builder.Build(true))
}

func TestDLRRReportBuilderConsumeOnlyIncludedReporters(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	require.True(t, builder.Record(1, 0x1000000000000000))
	require.True(t, builder.Record(2, 0x2000000000000000))

	block := builder.Build(true)
	require.NotNil(t, block)
	assert.Len(t, block.Reports, 2)

	// Both records were consumed, so a fresh report is required before the
	// builder answers again.
	assert.Nil(t, builder.Build(false))
}

func TestDLRRReportBuilderInterleavedUpdates(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	const (
		reporterA = 0x0A0A0A0A
		reporterB = 0x0B0B0B0B
		ntpA1     = uint64(0x1111111100000000)
		ntpA2     = uint64(0x2222222200000000)
		ntpB1     = uint64(0x3333333300000000)
		ntpB2     = uint64(0x4444444400000000)
	)

	require.True(t, builder.Record(reporterA, ntpA1))
	clock.Advance(10 * time.Millisecond)
	require.True(t, builder.Record(reporterB, ntpB1))
	clock.Advance(10 * time.Millisecond)

	// Reporter A sends a newer reference time; only A's timestamp and receipt
	// time move, while B keeps the receipt time of its own RRT.
	require.True(t, builder.Record(reporterA, ntpA2))
	clock.Advance(10 * time.Millisecond)

	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 2)
	assert.Equal(t, DLRRReport{
		SSRC:   reporterA,
		LastRR: wantLastRR(ntpA2),
		DLRR:   dlrrUnits(10 * time.Millisecond),
	}, block.Reports[0])
	assert.Equal(t, DLRRReport{
		SSRC:   reporterB,
		LastRR: wantLastRR(ntpB1),
		DLRR:   dlrrUnits(20 * time.Millisecond),
	}, block.Reports[1])

	// A later report from B replaces both B's timestamp and its receipt time.
	clock.Advance(5 * time.Millisecond)
	require.True(t, builder.Record(reporterB, ntpB2))
	clock.Advance(5 * time.Millisecond)

	block = builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 2)
	assert.Equal(t, DLRRReport{
		SSRC:   reporterA,
		LastRR: wantLastRR(ntpA2),
		DLRR:   dlrrUnits(20 * time.Millisecond),
	}, block.Reports[0])
	assert.Equal(t, DLRRReport{
		SSRC:   reporterB,
		LastRR: wantLastRR(ntpB2),
		DLRR:   dlrrUnits(5 * time.Millisecond),
	}, block.Reports[1])
}

func TestDLRRReportBuilderDuplicateRRT(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	const (
		reporter = 0xDEADBEEF
		ntp      = uint64(0x00000000ABCDEF01)
	)

	require.True(t, builder.Record(reporter, ntp))
	clock.Advance(20 * time.Millisecond)

	// A replay of the same reference time must not reset the delay: the RTT
	// sample still describes the original exchange.
	assert.False(t, builder.Record(reporter, ntp))

	// An older reference time is ignored for the same reason, even though it is
	// different from the stored timestamp.
	assert.False(t, builder.Record(reporter, ntp-1))

	clock.Advance(30 * time.Millisecond)
	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, wantLastRR(ntp), block.Reports[0].LastRR)
	assert.Equal(t, dlrrUnits(50*time.Millisecond), block.Reports[0].DLRR)

	// A newer reference time is accepted and restarts the delay.
	assert.True(t, builder.Record(reporter, ntp+0x10000))
	block = builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, wantLastRR(ntp+0x10000), block.Reports[0].LastRR)
	assert.Equal(t, uint32(0), block.Reports[0].DLRR)
}

func TestDLRRReportBuilderExpiry(t *testing.T) {
	clock := newManualClock(t)
	const maxAge = time.Second

	builder := NewDLRRReportBuilder(clock.Now, maxAge)
	require.True(t, builder.Record(1, 0x1111000011110000))
	require.True(t, builder.Record(2, 0x2222000022220000))

	// A record exactly at the age limit is still alive.
	clock.Advance(maxAge)
	block := builder.Build(false)
	require.NotNil(t, block)
	assert.Len(t, block.Reports, 2)

	// Past the limit both records are dropped, and the builder reports nothing
	// rather than answering with stale delays.
	clock.Advance(time.Nanosecond)
	assert.Nil(t, builder.Build(false))

	// Dropped records no longer block a replay: after expiry the same timestamp
	// is accepted and timed anew.
	clock.Advance(10 * time.Millisecond)
	assert.True(t, builder.Record(1, 0x1111000011110000))
	block = builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, dlrrUnits(0), block.Reports[0].DLRR)
}

func TestDLRRReportBuilderExpiryMixedReporters(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 100*time.Millisecond)

	require.True(t, builder.Record(1, 0x1111000011110000))
	clock.Advance(60 * time.Millisecond)
	require.True(t, builder.Record(2, 0x2222000022220000))
	clock.Advance(60 * time.Millisecond)

	// Reporter 1 has expired at 120ms while reporter 2 is still alive at 60ms.
	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, uint32(2), block.Reports[0].SSRC)
	assert.Equal(t, dlrrUnits(60*time.Millisecond), block.Reports[0].DLRR)
}

func TestDLRRReportBuilderZeroTimestamp(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	// RFC 3611 section 4.4: a reporter with neither wall clock nor elapsed time
	// may send zero. It carries no timing information and is not retained.
	assert.False(t, builder.Record(1, 0))
	assert.Nil(t, builder.Build(false))

	// Zero does not displace or reset an existing record either.
	const ntp = uint64(0x5000000000000000)
	require.True(t, builder.Record(1, ntp))
	clock.Advance(time.Second)
	assert.False(t, builder.Record(1, 0))

	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, wantLastRR(ntp), block.Reports[0].LastRR)
	assert.Equal(t, dlrrUnits(time.Second), block.Reports[0].DLRR)
}

func TestDLRRReportBuilderClockBackwards(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	require.True(t, builder.Record(1, 0x1000000000000000))
	clock.Advance(-250 * time.Millisecond) // The local wall clock steps backwards.

	// A negative delay is not representable; the DLRR field is clamped to zero
	// rather than wrapping around to a huge value.
	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, uint32(0), block.Reports[0].DLRR)

	// Time flowing backwards must not expire records either.
	expiring := NewDLRRReportBuilder(clock.Now, time.Second)
	require.True(t, expiring.Record(1, 0x1000000000000000))
	clock.Advance(-time.Hour)
	assert.NotNil(t, expiring.Build(false))
}

func TestDLRRReportBuilderDelayOverflow(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	require.True(t, builder.Record(1, 0x1000000000000000))
	clock.Advance(48 * time.Hour) // Far beyond the 32-bit 1/65536 s range.

	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, uint32(0xFFFFFFFF), block.Reports[0].DLRR)

	// The saturating value must also survive the wire format unchanged.
	raw, err := (&ExtendedReport{SenderSSRC: 1, Reports: []ReportBlock{block}}).Marshal()
	require.NoError(t, err)
	var decoded ExtendedReport
	require.NoError(t, decoded.Unmarshal(raw))
	require.Len(t, decoded.Reports, 1)
	decodedBlock, ok := decoded.Reports[0].(*DLRRReportBlock)
	require.True(t, ok)
	assert.Equal(t, block.Reports, decodedBlock.Reports)
}

func TestDLRRReportBuilderDelayQuantization(t *testing.T) {
	for _, test := range []struct {
		delay time.Duration
		want  uint32
	}{
		{delay: -time.Second, want: 0},
		{delay: 0, want: 0},
		{delay: time.Second, want: 65_536},
		{delay: time.Millisecond, want: 66}, // Rounds to nearest rather than truncating.
		{delay: 30 * time.Minute, want: 117_964_800},
	} {
		assert.Equal(t, test.want, durationToDLRRUnits(test.delay), "delay %s", test.delay)
	}
}

func TestDLRRReportBuilderRecordExtendedReport(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	xr := &ExtendedReport{
		SenderSSRC: 0x0F0F0F0F,
		Reports: []ReportBlock{
			&DLRRReportBlock{Reports: []DLRRReport{{SSRC: 1}}},
			&ReceiverReferenceTimeReportBlock{NTPTimestamp: 0x0F0F111122223333},
		},
	}
	assert.True(t, builder.RecordExtendedReport(xr))

	clock.Advance(40 * time.Millisecond)
	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, uint32(0x0F0F0F0F), block.Reports[0].SSRC)
	assert.Equal(t, wantLastRR(0x0F0F111122223333), block.Reports[0].LastRR)
	assert.Equal(t, dlrrUnits(40*time.Millisecond), block.Reports[0].DLRR)

	// Reports with no usable reference time are not recorded.
	assert.False(t, builder.RecordExtendedReport(nil))
	assert.False(t, builder.RecordExtendedReport(&ExtendedReport{
		SenderSSRC: 1,
		Reports:    []ReportBlock{&ReceiverReferenceTimeReportBlock{NTPTimestamp: 0}},
	}))
	assert.False(t, builder.RecordExtendedReport(&ExtendedReport{
		SenderSSRC: 1,
		Reports:    []ReportBlock{&ReceiverReferenceTimeReportBlock{}},
	}))
	assert.False(t, builder.RecordExtendedReport(&ExtendedReport{SenderSSRC: 1}))

	var typedNil *ReceiverReferenceTimeReportBlock
	assert.False(t, builder.RecordExtendedReport(&ExtendedReport{
		SenderSSRC: 7,
		Reports:    []ReportBlock{nil, typedNil},
	}))
}

func TestDLRRReportBuilderZeroValue(t *testing.T) {
	var builder DLRRReportBuilder

	// The zero value samples time.Now and never expires records.
	const ntp = uint64(0x0102030405060708)
	assert.True(t, builder.Record(1, ntp))

	block := builder.Build(false)
	require.NotNil(t, block)
	require.Len(t, block.Reports, 1)
	assert.Equal(t, wantLastRR(ntp), block.Reports[0].LastRR)
	assert.Equal(t, uint32(0), block.Reports[0].DLRR)

	assert.NotNil(t, builder.Build(true))
}

func TestDLRRReportBuilderReplyRoundTrip(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	const (
		reporterA = 0x88888888
		reporterB = 0x09090909
		ntpA      = uint64(0xDA8BD1FCDDDDA05A)
		ntpB      = uint64(0xE020A2A952A53FC0)
	)

	require.True(t, builder.Record(reporterA, ntpA))
	clock.Advance(123 * time.Millisecond)
	require.True(t, builder.Record(reporterB, ntpB))
	clock.Advance(250 * time.Millisecond)

	block := builder.Build(false)
	require.NotNil(t, block)

	// The reply has to be usable as a report block of a real XR packet.
	xr := &ExtendedReport{
		SenderSSRC: 0x01020304,
		Reports:    []ReportBlock{block},
	}
	raw, err := xr.Marshal()
	require.NoError(t, err)

	var decoded ExtendedReport
	require.NoError(t, decoded.Unmarshal(raw))
	require.Len(t, decoded.Reports, 1)

	decodedBlock, ok := decoded.Reports[0].(*DLRRReportBlock)
	require.True(t, ok)

	// The wire format preserves sub-block order, so the decoded reply must match
	// the built one without reordering. (Reporters are emitted in SSRC order,
	// which also makes the comparison independent of insertion order.)
	assert.Equal(t, block.Reports, decodedBlock.Reports)
	assert.Equal(t, []DLRRReport{
		{SSRC: reporterB, LastRR: wantLastRR(ntpB), DLRR: dlrrUnits(250 * time.Millisecond)},
		{SSRC: reporterA, LastRR: wantLastRR(ntpA), DLRR: dlrrUnits(373 * time.Millisecond)},
	}, decodedBlock.Reports)

	// The XR encoder inherits the DLRR sub-blocks as destination SSRCs.
	assert.Equal(t, []uint32{
		0x01020304,
		reporterB, // 0x09090909
		reporterA, // 0x88888888
	}, decoded.DestinationSSRC())
}

func TestDLRRReportBuilderConcurrentAccess(t *testing.T) {
	clock := newManualClock(t)
	builder := NewDLRRReportBuilder(clock.Now, 0)

	const (
		reporters = 8
		rounds    = 100
	)

	var waitGroup sync.WaitGroup
	for i := 1; i <= reporters; i++ {
		waitGroup.Add(1)

		go func(ssrc uint32) {
			defer waitGroup.Done()

			for j := range rounds {
				builder.Record(ssrc, uint64(ssrc)<<32|uint64(j)) //nolint:gosec // G115
				builder.RecordExtendedReport(&ExtendedReport{
					SenderSSRC: ssrc,
					Reports:    []ReportBlock{&ReceiverReferenceTimeReportBlock{NTPTimestamp: uint64(ssrc) << 32}},
				})
				if block := builder.Build(j%2 == 0); block != nil {
					assert.Len(t, block.Reports, len(block.DestinationSSRC()))
				}
			}
		}(uint32(i))
	}
	waitGroup.Wait()

	// Whatever interleaving occurred, a final non-consuming reply is well formed
	// and contains each reporter at most once, in a stable order.
	block := builder.Build(false)
	require.NotNil(t, block)
	assert.LessOrEqual(t, len(block.Reports), reporters)
	for i := 1; i < len(block.Reports); i++ {
		assert.Less(t, block.Reports[i-1].SSRC, block.Reports[i].SSRC)
	}
}
