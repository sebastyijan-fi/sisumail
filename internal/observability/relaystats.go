package observability

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

type RelayStats struct {
	start time.Time

	sshSessionsActive atomic.Int64

	tier1Accepted          atomic.Int64
	tier1Closed            atomic.Int64
	tier1OpenTimeout       atomic.Int64
	tier1ChannelOpenErrors atomic.Int64
	tier1PrefaceErrors     atomic.Int64

	tier1RejectNoSession  atomic.Int64
	tier1RejectUserCap    atomic.Int64
	tier1RejectSourceCap  atomic.Int64
	tier1RejectUnknownIP  atomic.Int64
	tier1RejectOpenFailed atomic.Int64

	spoolDelivered atomic.Int64
	spoolAcked     atomic.Int64

	chatLookupTotal   atomic.Int64
	chatLookupLimited atomic.Int64

	chatSendTotal          atomic.Int64
	chatSendLimited        atomic.Int64
	chatQueuedOffline      atomic.Int64
	chatDeliveredLive      atomic.Int64
	chatDeliveredFromQueue atomic.Int64
	chatAcked              atomic.Int64
}

func NewRelayStats() *RelayStats {
	return &RelayStats{start: time.Now()}
}

func (s *RelayStats) IncSSHSessions(delta int64) {
	s.sshSessionsActive.Add(delta)
}

func (s *RelayStats) IncTier1Accepted()          { s.tier1Accepted.Add(1) }
func (s *RelayStats) IncTier1Closed()            { s.tier1Closed.Add(1) }
func (s *RelayStats) IncTier1OpenTimeout()       { s.tier1OpenTimeout.Add(1) }
func (s *RelayStats) IncTier1ChannelOpenError()  { s.tier1ChannelOpenErrors.Add(1) }
func (s *RelayStats) IncTier1PrefaceError()      { s.tier1PrefaceErrors.Add(1) }
func (s *RelayStats) IncTier1RejectNoSession()   { s.tier1RejectNoSession.Add(1) }
func (s *RelayStats) IncTier1RejectUserCap()     { s.tier1RejectUserCap.Add(1) }
func (s *RelayStats) IncTier1RejectSourceCap()   { s.tier1RejectSourceCap.Add(1) }
func (s *RelayStats) IncTier1RejectUnknownIP()   { s.tier1RejectUnknownIP.Add(1) }
func (s *RelayStats) IncTier1RejectOpenFailed()  { s.tier1RejectOpenFailed.Add(1) }
func (s *RelayStats) IncSpoolDelivered()         { s.spoolDelivered.Add(1) }
func (s *RelayStats) IncSpoolAcked()             { s.spoolAcked.Add(1) }
func (s *RelayStats) IncChatLookupTotal()        { s.chatLookupTotal.Add(1) }
func (s *RelayStats) IncChatLookupLimited()      { s.chatLookupLimited.Add(1) }
func (s *RelayStats) IncChatSendTotal()          { s.chatSendTotal.Add(1) }
func (s *RelayStats) IncChatSendLimited()        { s.chatSendLimited.Add(1) }
func (s *RelayStats) IncChatQueuedOffline()      { s.chatQueuedOffline.Add(1) }
func (s *RelayStats) IncChatDeliveredLive()      { s.chatDeliveredLive.Add(1) }
func (s *RelayStats) IncChatDeliveredFromQueue() { s.chatDeliveredFromQueue.Add(1) }
func (s *RelayStats) IncChatAcked()              { s.chatAcked.Add(1) }

func (s *RelayStats) Prometheus() string {
	var b strings.Builder
	write := func(name string, v int64) {
		fmt.Fprintf(&b, "%s %d\n", name, v)
	}
	write("sisumail_uptime_seconds", int64(time.Since(s.start).Seconds()))
	write("sisumail_ssh_sessions_active", s.sshSessionsActive.Load())

	write("sisumail_tier1_connections_accepted_total", s.tier1Accepted.Load())
	write("sisumail_tier1_connections_closed_total", s.tier1Closed.Load())
	write("sisumail_tier1_channel_open_timeout_total", s.tier1OpenTimeout.Load())
	write("sisumail_tier1_channel_open_error_total", s.tier1ChannelOpenErrors.Load())
	write("sisumail_tier1_preface_write_error_total", s.tier1PrefaceErrors.Load())
	write("sisumail_tier1_reject_no_session_total", s.tier1RejectNoSession.Load())
	write("sisumail_tier1_reject_user_cap_total", s.tier1RejectUserCap.Load())
	write("sisumail_tier1_reject_source_cap_total", s.tier1RejectSourceCap.Load())
	write("sisumail_tier1_reject_unknown_dest_total", s.tier1RejectUnknownIP.Load())
	write("sisumail_tier1_reject_channel_open_failed_total", s.tier1RejectOpenFailed.Load())

	write("sisumail_spool_delivered_total", s.spoolDelivered.Load())
	write("sisumail_spool_acked_total", s.spoolAcked.Load())

	write("sisumail_chat_lookup_total", s.chatLookupTotal.Load())
	write("sisumail_chat_lookup_limited_total", s.chatLookupLimited.Load())
	write("sisumail_chat_send_total", s.chatSendTotal.Load())
	write("sisumail_chat_send_limited_total", s.chatSendLimited.Load())
	write("sisumail_chat_queued_offline_total", s.chatQueuedOffline.Load())
	write("sisumail_chat_delivered_live_total", s.chatDeliveredLive.Load())
	write("sisumail_chat_delivered_from_queue_total", s.chatDeliveredFromQueue.Load())
	write("sisumail_chat_acked_total", s.chatAcked.Load())
	return b.String()
}
