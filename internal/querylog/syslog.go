package querylog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Networks supported by the syslog forwarding.
const (
	SyslogNetworkUDP = "udp"
	SyslogNetworkTCP = "tcp"
)

// Formats supported by the syslog forwarding.
const (
	SyslogFormatRFC5424 = "rfc5424"
	SyslogFormatRFC3164 = "rfc3164"
)

const (
	// syslogSeverityInfo is the severity value used for all messages.  Query
	// log entries are informational.
	syslogSeverityInfo = 6

	// syslogFacilityMax is the maximum valid syslog facility value.
	syslogFacilityMax = 23

	// DefaultSyslogTag is used when [SyslogConfig.Tag] is empty.
	DefaultSyslogTag = "AdGuardHome"

	// DefaultSyslogFacility is local0.  Note that the zero facility value,
	// kern, is not useful for query logging, so it is treated as unset by
	// [SyslogConfig.normalize].
	DefaultSyslogFacility = 16

	// maxSyslogTagLen is the maximum length of the APP-NAME field, see
	// RFC 5424, section 6.2.4.
	maxSyslogTagLen = 48

	// syslogNilValue is the NILVALUE placeholder defined by RFC 5424.
	syslogNilValue = "-"

	// syslogQueueSize is the maximum number of entries waiting to be sent.
	// Entries added to a full queue are dropped.
	syslogQueueSize = 1024

	// maxSyslogRules is the maximum number of filtering rules included into a
	// single message.  It keeps messages small enough to not be fragmented by
	// the network.
	maxSyslogRules = 10

	// syslogDialTimeout is the timeout for establishing a connection.
	syslogDialTimeout = 5 * time.Second

	// syslogWriteTimeout is the timeout for writing a single message.
	syslogWriteTimeout = 5 * time.Second

	// syslogDrainTimeout is the timeout for sending the entries left in the
	// queue during shutdown.
	syslogDrainTimeout = 3 * time.Second

	// syslogStopTimeout is the timeout for waiting for the sender goroutine to
	// stop.
	syslogStopTimeout = syslogDrainTimeout + 2*time.Second

	// syslogInitialBackoff is the initial delay before the next reconnection
	// attempt.
	syslogInitialBackoff = 1 * time.Second

	// syslogMaxBackoff is the maximum delay before the next reconnection
	// attempt.
	syslogMaxBackoff = 30 * time.Second

	// syslogDropsLogIvl is the minimum interval between the messages about
	// dropped entries.
	syslogDropsLogIvl = 1 * time.Second
)

// SyslogConfig is the configuration for forwarding query log entries to a
// remote syslog server.
type SyslogConfig struct {
	// Network is the network to use, either [SyslogNetworkUDP] or
	// [SyslogNetworkTCP].
	Network string

	// Address is the host:port of the syslog server.
	Address string

	// Format is the message format, either [SyslogFormatRFC5424] or
	// [SyslogFormatRFC3164].
	Format string

	// Tag is the APP-NAME field of the message.
	Tag string

	// Hostname is the HOSTNAME field of the message.  If empty, the OS
	// hostname is used.
	Hostname string

	// Facility is the syslog facility, from 0 to 23.
	Facility int

	// Enabled tells if the forwarding to syslog is enabled.  It is
	// independent of [Config.Enabled], so that the query log can be forwarded
	// without being stored locally.
	Enabled bool
}

// normalize replaces the empty fields of c with their default values.  It must
// be called before [SyslogConfig.validate].
func (c *SyslogConfig) normalize() {
	if c.Network == "" {
		c.Network = SyslogNetworkUDP
	}

	if c.Format == "" {
		c.Format = SyslogFormatRFC5424
	}

	if c.Tag == "" {
		c.Tag = DefaultSyslogTag
	}

	if c.Facility == 0 {
		c.Facility = DefaultSyslogFacility
	}
}

// validate returns an error if c is not a valid configuration.  It must be
// called after [SyslogConfig.normalize].
func (c *SyslogConfig) validate() (err error) {
	if !c.Enabled {
		// The rest of the fields are not used when the forwarding is disabled.
		return nil
	}

	if c.Address == "" {
		return errors.Error("address is empty")
	}

	_, _, err = net.SplitHostPort(c.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	err = validateSyslogNetwork(c.Network)
	if err != nil {
		return err
	}

	err = validateSyslogFormat(c.Format)
	if err != nil {
		return err
	}

	if c.Facility < 0 || c.Facility > syslogFacilityMax {
		return fmt.Errorf("invalid facility: %d", c.Facility)
	}

	err = validateSyslogHostname(c.Hostname)
	if err != nil {
		return err
	}

	return validateSyslogTag(c.Tag)
}

// validateSyslogNetwork returns an error if network is not a supported network
// for connecting to the syslog server.
func validateSyslogNetwork(network string) (err error) {
	switch network {
	case SyslogNetworkUDP, SyslogNetworkTCP:
		return nil
	default:
		return fmt.Errorf("invalid network: %q", network)
	}
}

// validateSyslogFormat returns an error if format is not a supported syslog
// message format.
func validateSyslogFormat(format string) (err error) {
	switch format {
	case SyslogFormatRFC5424, SyslogFormatRFC3164:
		return nil
	default:
		return fmt.Errorf("invalid format: %q", format)
	}
}

// validateSyslogHostname returns an error if hostname is not empty and is not
// a valid hostname.
func validateSyslogHostname(hostname string) (err error) {
	if hostname == "" {
		return nil
	}

	err = netutil.ValidateHostname(hostname)
	if err != nil {
		return fmt.Errorf("invalid hostname: %w", err)
	}

	return nil
}

// validateSyslogTag returns an error if tag cannot be used as the APP-NAME
// field of a syslog message.
func validateSyslogTag(tag string) (err error) {
	if tag == "" {
		return errors.Error("tag is empty")
	}

	if len(tag) > maxSyslogTagLen {
		return fmt.Errorf("tag is too long: %d > %d", len(tag), maxSyslogTagLen)
	}

	for i, r := range tag {
		// The APP-NAME field must consist of printable ASCII characters, see
		// RFC 5424, section 6.2.4.
		if r <= ' ' || r > '~' {
			return fmt.Errorf("invalid character in tag at %d: %q", i, r)
		}
	}

	return nil
}

// syslogSender forwards query log entries to a remote syslog server.
//
// All network operations are performed in a separate goroutine, so that
// sending never blocks the DNS request processing.  See [queryLog.Add].
type syslogSender struct {
	// logger is used for logging the operation of the sender.  It must not be
	// nil.
	logger *slog.Logger

	// conf returns the current configuration.  It must not be nil.
	conf func() (c SyslogConfig)

	// ch is the queue of entries waiting to be sent.  Entries added to a full
	// queue are dropped to avoid blocking the caller.
	ch chan *logEntry

	// done is closed to signal the sender to stop.
	done chan struct{}

	// stopped is closed by [syslogSender.run] when it returns.
	stopped chan struct{}

	// doneOnce makes [syslogSender.shutdown] idempotent.
	doneOnce *sync.Once

	// started is true once [syslogSender.run] has begun.  It tells
	// [syslogSender.shutdown] whether there is anything to wait for.
	started *atomic.Bool

	// dropped is the number of entries dropped because the queue was full.
	dropped *atomic.Uint64

	// The fields above are safe for concurrent use, while the ones below are
	// the mutable connection state that is only accessed from the
	// [syslogSender.run] goroutine.

	// conn is the current connection to the syslog server, nil if not
	// connected.
	conn net.Conn

	// connKey identifies conn.
	connKey syslogConnKey

	// fmtter is the current formatter, nil if not initialized.
	fmtter *syslogFormatter

	// fmtterKey identifies fmtter.
	fmtterKey syslogFormatterKey

	// backoff is the current reconnect backoff delay.
	backoff time.Duration

	// nextAttempt is the earliest time at which dialing the server again is
	// attempted.
	nextAttempt time.Time

	// lastDrops is the time of the last log message about dropped entries.
	lastDrops time.Time
}

// newSyslogSender returns a new sender.  conf must not be nil.
func newSyslogSender(
	logger *slog.Logger,
	conf func() (c SyslogConfig),
) (s *syslogSender) {
	return &syslogSender{
		logger:   logger,
		conf:     conf,
		ch:       make(chan *logEntry, syslogQueueSize),
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
		doneOnce: &sync.Once{},
		started:  &atomic.Bool{},
		dropped:  &atomic.Uint64{},
	}
}

// enqueue adds entry to the sending queue.  It never blocks: if the queue is
// full, the entry is dropped and the drop counter is incremented.  It is safe
// for concurrent use.
func (s *syslogSender) enqueue(entry *logEntry) {
	select {
	case s.ch <- entry:
		// Go on.
	default:
		s.dropped.Add(1)
	}
}

// run sends the queued entries to the syslog server until ctx is canceled or
// [syslogSender.shutdown] is called.  It is intended to be used as a
// goroutine.
func (s *syslogSender) run(ctx context.Context) {
	s.started.Store(true)

	defer slogutil.RecoverAndLog(ctx, s.logger)
	defer close(s.stopped)
	defer s.closeConn(ctx)

	for {
		select {
		case <-s.done:
			drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), syslogDrainTimeout)
			s.drain(drainCtx)
			cancel()

			return
		case <-ctx.Done():
			return
		case entry := <-s.ch:
			s.send(ctx, entry)
		}
	}
}

// drain sends the entries left in the queue until ctx is done.
func (s *syslogSender) drain(ctx context.Context) {
	for ctx.Err() == nil {
		select {
		case entry := <-s.ch:
			s.send(ctx, entry)
		default:
			return
		}
	}
}

// send attempts to send entry to the configured syslog server.  It never
// returns an error: a failed send only drops the entry, since blocking the DNS
// request processing is not an option.  It must only be called from the
// [syslogSender.run] goroutine.
func (s *syslogSender) send(ctx context.Context, entry *logEntry) {
	conf := s.conf()
	if !conf.Enabled {
		return
	}

	fmtter := s.formatterForConf(conf)

	_, ok := s.connForConf(ctx, conf)
	if !ok {
		return
	}

	ok = s.writeEntry(ctx, fmtter, entry)
	if !ok {
		return
	}

	s.logDrops(ctx)
}

// formatterForConf returns the current formatter, recreating it if conf has
// changed since the last call.
func (s *syslogSender) formatterForConf(conf SyslogConfig) (fmtter *syslogFormatter) {
	key := newSyslogFormatterKey(conf)
	if s.fmtter == nil || key != s.fmtterKey {
		s.fmtter = newSyslogFormatter(conf, resolveSyslogHostname(conf.Hostname))
		s.fmtterKey = key
	}

	return s.fmtter
}

// connForConf returns the connection for conf.  It reconnects if the target
// server has changed and dials if there is no connection and the reconnect
// backoff has elapsed.  It returns false if there is no connection at the
// moment.
//
// It must only be called from the [syslogSender.run] goroutine.
func (s *syslogSender) connForConf(ctx context.Context, conf SyslogConfig) (conn net.Conn, ok bool) {
	key := syslogConnKey{
		network: conf.Network,
		address: conf.Address,
	}
	if s.conn != nil && key != s.connKey {
		// The server address has changed, reconnect.
		s.closeConn(ctx)

		s.backoff = 0
		s.nextAttempt = time.Time{}
	}

	if s.conn != nil {
		return s.conn, true
	}

	if time.Now().Before(s.nextAttempt) {
		// The server is still considered unreachable.
		return nil, false
	}

	dialed, err := net.DialTimeout(conf.Network, conf.Address, syslogDialTimeout)
	if err != nil {
		s.logger.WarnContext(
			ctx,
			"dialing syslog server",
			"address", conf.Address,
			slogutil.KeyError, err,
		)

		s.backoff = nextSyslogBackoff(s.backoff)
		s.nextAttempt = time.Now().Add(s.backoff)

		return nil, false
	}

	s.conn = dialed
	s.connKey = key
	s.backoff = 0

	return dialed, true
}

// writeEntry sends the message for entry over the current connection.  It
// resets the connection state and schedules a reconnect on failure.
//
// It must only be called from the [syslogSender.run] goroutine.
func (s *syslogSender) writeEntry(ctx context.Context, fmtter *syslogFormatter, entry *logEntry) (ok bool) {
	_ = s.conn.SetWriteDeadline(time.Now().Add(syslogWriteTimeout))

	_, err := s.conn.Write(fmtter.message(entry))
	if err != nil {
		s.logger.WarnContext(ctx, "sending to syslog server", slogutil.KeyError, err)

		s.closeConn(ctx)
		s.backoff = nextSyslogBackoff(s.backoff)
		s.nextAttempt = time.Now().Add(s.backoff)

		return false
	}

	return true
}

// closeConn closes the current connection, if any, and forgets it.
//
// It must only be called from the [syslogSender.run] goroutine.
func (s *syslogSender) closeConn(ctx context.Context) {
	if s.conn == nil {
		return
	}

	closeErr := s.conn.Close()
	if closeErr != nil {
		s.logger.DebugContext(ctx, "closing syslog connection", slogutil.KeyError, closeErr)
	}

	s.conn = nil
}

// logDrops logs the number of entries dropped since the last call if it is
// nonzero and the log interval has elapsed.
func (s *syslogSender) logDrops(ctx context.Context) {
	dropped := s.dropped.Swap(0)
	if dropped == 0 || time.Since(s.lastDrops) < syslogDropsLogIvl {
		return
	}

	s.logger.WarnContext(ctx, "dropping syslog entries", "count", dropped)

	s.lastDrops = time.Now()
}

// shutdown stops the sender and waits for it to finish.  It is safe to call it
// multiple times.
func (s *syslogSender) shutdown() {
	s.doneOnce.Do(func() { close(s.done) })

	if !s.started.Load() {
		// The sender was never started, so there is nothing to wait for.  If
		// it is started later, it stops immediately, since done is closed.
		return
	}

	timer := time.NewTimer(syslogStopTimeout)
	defer timer.Stop()

	select {
	case <-s.stopped:
		// Go on.
	case <-timer.C:
		s.logger.Warn("timed out waiting for the syslog sender to stop")
	}
}

// syslogConnKey identifies the connection parameters.  When any of them
// changes, the connection must be re-established.
type syslogConnKey struct {
	// network is the network of the connection.
	network string

	// address is the address of the connection.
	address string
}

// nextSyslogBackoff returns the next reconnection delay.
func nextSyslogBackoff(cur time.Duration) (next time.Duration) {
	if cur <= 0 {
		return syslogInitialBackoff
	}

	next = cur * 2
	if next > syslogMaxBackoff {
		return syslogMaxBackoff
	}

	return next
}

// resolveSyslogHostname returns the HOSTNAME field value.  If configured is
// empty, the OS hostname is used.
func resolveSyslogHostname(configured string) (hostname string) {
	if configured != "" {
		return configured
	}

	hostname, err := os.Hostname()
	if err != nil {
		return syslogNilValue
	}

	return hostname
}

// syslogFormatterKey identifies the formatter parameters.  When any of the
// fields changes, the formatter must be recreated.
type syslogFormatterKey struct {
	format   string
	tag      string
	hostname string
	facility int
}

// newSyslogFormatterKey returns the formatter key for conf.
func newSyslogFormatterKey(conf SyslogConfig) (k syslogFormatterKey) {
	return syslogFormatterKey{
		format:   conf.Format,
		tag:      conf.Tag,
		hostname: conf.Hostname,
		facility: conf.Facility,
	}
}

// syslogFormatter formats log entries as syslog messages.
type syslogFormatter struct {
	// hostname is the resolved HOSTNAME field value.
	hostname string

	// tag is the APP-NAME field value.
	tag string

	// format is the message format, either [SyslogFormatRFC5424] or
	// [SyslogFormatRFC3164].
	format string

	// pid is the process identifier used by the RFC 3164 format.
	pid int

	// pri is the priority value, calculated from the facility and the
	// severity.
	pri int
}

// newSyslogFormatter returns a formatter for conf.  hostname must be the
// resolved HOSTNAME field value.
func newSyslogFormatter(conf SyslogConfig, hostname string) (f *syslogFormatter) {
	return &syslogFormatter{
		hostname: hostname,
		tag:      conf.Tag,
		format:   conf.Format,
		pid:      os.Getpid(),
		pri:      conf.Facility*8 + syslogSeverityInfo,
	}
}

// message returns the syslog message for entry.
func (f *syslogFormatter) message(entry *logEntry) (msg []byte) {
	payload, err := json.Marshal(newSyslogPayload(entry))
	if err != nil {
		// Should not happen, since the payload consists of simple types only.
		payload = []byte("{}")
	}

	if f.format == SyslogFormatRFC3164 {
		return f.appendRFC3164(nil, entry.Time, payload)
	}

	return f.appendRFC5424(nil, entry.Time, payload)
}

// appendRFC5424 appends the RFC 5424 representation of a message to dst.
//
//	<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
func (f *syslogFormatter) appendRFC5424(dst []byte, ts time.Time, payload []byte) (msg []byte) {
	dst = append(dst, '<')
	dst = strconv.AppendInt(dst, int64(f.pri), 10)
	dst = append(dst, '>', '1', ' ')
	dst = ts.AppendFormat(dst, time.RFC3339Nano)
	dst = append(dst, ' ')
	dst = append(dst, f.hostname...)
	dst = append(dst, ' ')
	dst = append(dst, f.tag...)

	// PROCID, MSGID, and STRUCTURED-DATA are set to NILVALUE, the entry data
	// is carried by the JSON payload.
	dst = append(dst, ' ', '-', ' ', '-', ' ', '-', ' ')
	dst = append(dst, payload...)

	return dst
}

// appendRFC3164 appends the RFC 3164 representation of a message to dst.
//
//	<PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG
//
// Note that the RFC 3164 timestamp has neither the year nor the time zone,
// which makes it ambiguous.  Prefer RFC 5424 unless an old collector requires
// it.
func (f *syslogFormatter) appendRFC3164(dst []byte, ts time.Time, payload []byte) (msg []byte) {
	dst = append(dst, '<')
	dst = strconv.AppendInt(dst, int64(f.pri), 10)
	dst = append(dst, '>')
	dst = ts.AppendFormat(dst, time.Stamp)
	dst = append(dst, ' ')
	dst = append(dst, f.hostname...)
	dst = append(dst, ' ')
	dst = append(dst, f.tag...)
	dst = append(dst, '[')
	dst = strconv.AppendInt(dst, int64(f.pid), 10)
	dst = append(dst, ']', ':', ' ')
	dst = append(dst, payload...)

	return dst
}

// syslogRule is a filtering rule as it appears in a syslog message.
type syslogRule struct {
	// Text is the text of the rule.
	Text string `json:"text,omitempty"`

	// FilterListID is the ID of the filter list the rule belongs to.
	FilterListID int64 `json:"filter_list_id,omitempty"`
}

// syslogPayload is the JSON document sent as the message body.  It is the
// machine-readable representation of a [logEntry], so the fields that require
// an additional lookup are omitted.
type syslogPayload struct {
	// Time is the time of the request in the RFC 3339 format.
	Time string `json:"time"`

	ClientID    string      `json:"client_id,omitempty"`
	ClientProto ClientProto `json:"client_proto,omitempty"`
	ClientIP    string      `json:"client_ip,omitempty"`

	QHost  string `json:"q_host"`
	QType  string `json:"q_type"`
	QClass string `json:"q_class"`

	// ReqECS is the IP network extracted from the EDNS Client-Subnet option.
	ReqECS string `json:"req_ecs,omitempty"`

	// Response is the response code of the DNS answer.
	Response string `json:"response,omitempty"`

	Upstream string `json:"upstream,omitempty"`

	// Reason is the human-readable filtering reason, for example
	// "FilteredBlackList".
	Reason string `json:"reason,omitempty"`

	// ServiceName is the name of the blocked service, if any.
	ServiceName string `json:"service_name,omitempty"`

	// CanonName is the CNAME value from the lookup rewrite result, if any.
	CanonName string `json:"canon_name,omitempty"`

	// Rules are the filtering rules applied to the request.
	Rules []syslogRule `json:"rules,omitempty"`

	// ElapsedMS is the time spent processing the request, in milliseconds.
	ElapsedMS int64 `json:"elapsed_ms"`

	// Cached is true if the response was served from the cache.
	Cached bool `json:"cached,omitempty"`

	// AD is true if the response had the Authenticated Data bit set.
	AD bool `json:"ad,omitempty"`

	// IsFiltered is true if the request was filtered.
	IsFiltered bool `json:"is_filtered,omitempty"`
}

// newSyslogPayload returns the payload for entry.
func newSyslogPayload(entry *logEntry) (p *syslogPayload) {
	p = &syslogPayload{
		Time:        entry.Time.Format(time.RFC3339Nano),
		ClientID:    entry.ClientID,
		ClientProto: entry.ClientProto,
		QHost:       entry.QHost,
		QType:       entry.QType,
		QClass:      entry.QClass,
		ReqECS:      entry.ReqECS,
		Response:    responseCode(entry.Answer),
		Upstream:    entry.Upstream,
		Reason:      entry.Result.Reason.String(),
		ServiceName: entry.Result.ServiceName,
		CanonName:   entry.Result.CanonName,
		ElapsedMS:   entry.Elapsed.Milliseconds(),
		Cached:      entry.Cached,
		AD:          entry.AuthenticatedData,
		IsFiltered:  entry.Result.IsFiltered,
	}

	if entry.IP != nil {
		p.ClientIP = entry.IP.String()
	}

	rules := entry.Result.Rules
	if len(rules) > maxSyslogRules {
		rules = rules[:maxSyslogRules]
	}

	for _, r := range rules {
		p.Rules = append(p.Rules, syslogRule{
			Text:         r.Text,
			FilterListID: int64(r.FilterListID),
		})
	}

	return p
}

// responseCode returns the response code of the DNS message in answer, if any.
func responseCode(answer []byte) (code string) {
	if len(answer) == 0 {
		return ""
	}

	msg := &dns.Msg{}
	err := msg.Unpack(answer)
	if err != nil {
		return ""
	}

	return dns.RcodeToString[msg.Rcode]
}
