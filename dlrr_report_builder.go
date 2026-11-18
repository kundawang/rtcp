// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"math"
	"slices"
	"sync"
	"time"
)

// DLRRReportBuilder answers Receiver Reference Time report blocks (RFC 3611
// section 4.4) with DLRR report blocks (RFC 3611 section 4.5).
//
// The receiver of an ExtendedReport never has to retain the NTP timestamp
// itself: Record stores it together with the local instant at which it was
// received, and Build converts those records into the LastRR and delay fields
// of a DLRRReportBlock.
//
// Delays are measured on the local clock, never from the reported NTP
// timestamps. When the clock passed to NewDLRRReportBuilder is time.Now (the
// default), the elapsed time is taken from the monotonic clock reading, so wall
// clock jumps do not affect the reply.
//
// The zero value is ready to use: it samples time.Now and keeps records
// forever. A DLRRReportBuilder is safe for concurrent use by multiple
// goroutines, but must not be copied after first use.
type DLRRReportBuilder struct {
	mu        sync.Mutex
	now       func() time.Time
	maxAge    time.Duration
	reporters map[uint32]rrtRecord
}

// rrtRecord is the local state kept for one reporter.
type rrtRecord struct {
	ntpTimestamp uint64
	receivedAt   time.Time
}

const (
	// dlrrUnitsPerSecond is the resolution of the DLRR field (RFC 3611 section 4.5).
	dlrrUnitsPerSecond = 65536
	// maxDLRRDelay is the longest delay representable in the DLRR field.
	maxDLRRDelay = time.Duration(math.MaxUint32) * time.Second / dlrrUnitsPerSecond
)

// NewDLRRReportBuilder returns a DLRRReportBuilder that timestamps incoming
// records with now and expires them once they are older than maxAge.
//
// now should return times carrying a monotonic reading, as time.Now does; a nil
// now selects time.Now. A non-positive maxAge disables expiry.
func NewDLRRReportBuilder(now func() time.Time, maxAge time.Duration) *DLRRReportBuilder {
	if now == nil {
		now = time.Now
	}

	return &DLRRReportBuilder{
		now:       now,
		maxAge:    maxAge,
		reporters: make(map[uint32]rrtRecord),
	}
}

// Record stores ntpTimestamp as the most recent Receiver Reference Time
// reported by ssrc, timestamped with the local clock. It reports whether the
// record was stored.
//
// A zero NTP timestamp (RFC 3611 section 4.4 allows one when the reporter has
// no wall clock) cannot be used for RTT measurement and is never stored. While
// a live record exists for ssrc, a duplicate or older NTP timestamp is ignored,
// so replaying an RRT cannot reset the delay measured for it. Once a record has
// expired any timestamp, including a replay, is accepted.
func (b *DLRRReportBuilder) Record(ssrc uint32, ntpTimestamp uint64) bool {
	if ntpTimestamp == 0 {
		return false
	}

	return b.recordAt(ssrc, ntpTimestamp, b.clock())
}

// RecordExtendedReport records every Receiver Reference Time report block
// carried by xr under xr.SenderSSRC, the participant that sent the report. It
// reports whether at least one record was stored.
func (b *DLRRReportBuilder) RecordExtendedReport(xr *ExtendedReport) bool {
	if xr == nil {
		return false
	}

	now := b.clock()
	recorded := false
	for _, block := range xr.Reports {
		rrt, ok := block.(*ReceiverReferenceTimeReportBlock)
		if !ok || rrt == nil {
			continue
		}
		if b.recordAt(xr.SenderSSRC, rrt.NTPTimestamp, now) {
			recorded = true
		}
	}

	return recorded
}

// Build assembles a DLRRReportBlock answering the most recent RRT of every
// reporter, in ascending SSRC order. Expired records are discarded and never
// reported.
//
// When consume is true the records included in the reply are removed, so a
// later Build no longer reports them. When consume is false the state is
// retained, and later builds keep answering the same RRT with a growing delay.
//
// Build returns nil when no reporter has a live record, which lets callers omit
// the block from an outgoing ExtendedReport.
func (b *DLRRReportBuilder) Build(consume bool) *DLRRReportBlock {
	now := b.clock()

	b.mu.Lock()
	defer b.mu.Unlock()

	ssrcs := make([]uint32, 0, len(b.reporters))
	for ssrc := range b.reporters {
		ssrcs = append(ssrcs, ssrc)
	}
	slices.Sort(ssrcs)

	reports := make([]DLRRReport, 0, len(ssrcs))
	for _, ssrc := range ssrcs {
		record := b.reporters[ssrc]
		age := now.Sub(record.receivedAt)
		if b.expired(age) {
			delete(b.reporters, ssrc)

			continue
		}
		reports = append(reports, DLRRReport{
			SSRC:   ssrc,
			LastRR: lastRR(record.ntpTimestamp),
			DLRR:   durationToDLRRUnits(age),
		})
		if consume {
			delete(b.reporters, ssrc)
		}
	}
	if len(reports) == 0 {
		return nil
	}

	block := &DLRRReportBlock{Reports: reports}
	// Marshal would set this up anyway, but returning a complete block lets
	// callers inspect or compare it before it goes on the wire.
	block.setupBlockHeader()

	return block
}

// recordAt stores a record using a previously sampled local instant.
func (b *DLRRReportBuilder) recordAt(ssrc uint32, ntpTimestamp uint64, now time.Time) bool {
	if ntpTimestamp == 0 {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.reporters == nil {
		b.reporters = make(map[uint32]rrtRecord)
	}

	previous, ok := b.reporters[ssrc]
	if ok &&
		!b.expired(now.Sub(previous.receivedAt)) &&
		!ntpTimestampNewer(ntpTimestamp, previous.ntpTimestamp) {
		return false
	}

	b.reporters[ssrc] = rrtRecord{ntpTimestamp: ntpTimestamp, receivedAt: now}

	return true
}

// clock samples the local clock.
func (b *DLRRReportBuilder) clock() time.Time {
	if b.now == nil {
		return time.Now()
	}

	return b.now()
}

// expired reports whether a record of the given age has outlived maxAge.
func (b *DLRRReportBuilder) expired(age time.Duration) bool {
	return b.maxAge > 0 && age > b.maxAge
}

// lastRR returns the middle 32 bits of an NTP timestamp, as required by the
// LastRR field of a DLRR sub-block (RFC 3611 section 4.5).
func lastRR(ntpTimestamp uint64) uint32 {
	return uint32((ntpTimestamp >> 16) & math.MaxUint32) //nolint:gosec // G115 // keeps the middle 32 bits.
}

// durationToDLRRUnits converts a local elapsed time to the 1/65536 second units
// of the DLRR field, rounding to nearest and saturating at the field width.
// Negative durations, produced when the local clock moved backwards, become
// zero.
func durationToDLRRUnits(delay time.Duration) uint32 {
	if delay <= 0 {
		return 0
	}
	if delay >= maxDLRRDelay {
		return math.MaxUint32
	}

	// Split the product to keep a saturating multiplication out of the way:
	// whole seconds fit comfortably, and the sub-second remainder is scaled
	// separately before rounding.
	seconds := delay / time.Second
	remainder := uint64(delay % time.Second)
	units := uint64(seconds)*dlrrUnitsPerSecond +
		(remainder*dlrrUnitsPerSecond+uint64(time.Second)/2)/uint64(time.Second)

	return uint32(units) //nolint:gosec // G115 // delay < maxDLRRDelay keeps units within 32 bits.
}

// ntpTimestampNewer reports whether candidate is later than previous, using
// serial number arithmetic so the comparison survives the NTP era rollover.
func ntpTimestampNewer(candidate, previous uint64) bool {
	diff := candidate - previous

	return diff != 0 && diff < 1<<63
}
