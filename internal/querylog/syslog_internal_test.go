package querylog

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syslogTestTimeout is the timeout for the syslog tests which use the network.
// It is longer than testTimeout, because a test needs to dial a connection
// and send a message in addition to the usual work.
const syslogTestTimeout = 5 * time.Second

// testSyslogHostname is the HOSTNAME field value used in tests.
const testSyslogHostname = "test-host"

// testSyslogEntry returns a log entry used by the formatting tests.
func testSyslogEntry() (entry *logEntry) {
	return &logEntry{
		Time:   time.Date(2026, 9, 10, 12, 34, 56, 789000000, time.UTC),
		QHost:  "ads.example.org",
		QType:  "A",
		QClass: "IN",
		IP:     net.IPv4(192, 168, 1, 5),
		Result: filtering.Result{
			Reason:     filtering.FilteredBlockList,
			IsFiltered: true,
			Rules: []*filtering.ResultRule{{
				Text:         "||ads.example^",
				FilterListID: 1,
			}},
		},
		Elapsed: 12 * time.Millisecond,
	}
}

// testSyslogConfig returns a valid syslog configuration which uses network and
// address as its destination.
func testSyslogConfig(network, address string) (conf SyslogConfig) {
	return SyslogConfig{
		Enabled:  true,
		Network:  network,
		Address:  address,
		Format:   SyslogFormatRFC5424,
		Tag:      DefaultSyslogTag,
		Hostname: testSyslogHostname,
		Facility: DefaultSyslogFacility,
	}
}

// newSyslogTestQueryLog returns a query log with the local storage disabled
// and the syslog forwarding configured with conf.  It also starts the query
// log and registers the cleanup.
func newSyslogTestQueryLog(tb testing.TB, conf SyslogConfig) (l *queryLog) {
	tb.Helper()

	l, err := newQueryLog(Config{
		Logger: testLogger,

		// Disable the local storage entirely to check that the forwarding is
		// independent of it.
		Enabled:     false,
		FileEnabled: false,

		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     tb.TempDir(),
		Syslog:      conf,
	})
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, syslogTestTimeout)
	require.NoError(tb, l.Start(ctx))

	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return l.Shutdown(ctx)
	})

	return l
}

// requireSyslogPayload parses the JSON payload of msg and asserts that it
// contains the expected fields.
func requireSyslogPayload(t *testing.T, msg string) {
	t.Helper()

	idx := strings.IndexByte(msg, '{')
	require.NotEqual(t, -1, idx, "no JSON payload in %q", msg)

	var p syslogPayload
	require.NoError(t, json.Unmarshal([]byte(msg[idx:]), &p))

	assert.Equal(t, "ads.example.org", p.QHost)
	assert.Equal(t, "A", p.QType)
	assert.Equal(t, "IN", p.QClass)
	assert.Equal(t, "192.168.1.5", p.ClientIP)
	assert.Equal(t, "FilteredBlackList", p.Reason)
	assert.True(t, p.IsFiltered)
	assert.Equal(t, int64(12), p.ElapsedMS)

	require.Len(t, p.Rules, 1)
	assert.Equal(t, "||ads.example^", p.Rules[0].Text)
	assert.Equal(t, int64(1), p.Rules[0].FilterListID)
}

func TestSyslogConfig_normalize(t *testing.T) {
	conf := &SyslogConfig{}
	conf.normalize()

	assert.Equal(t, SyslogNetworkUDP, conf.Network)
	assert.Equal(t, SyslogFormatRFC5424, conf.Format)
	assert.Equal(t, DefaultSyslogTag, conf.Tag)
	assert.Equal(t, DefaultSyslogFacility, conf.Facility)
}

func TestSyslogConfig_validate(t *testing.T) {
	// valid returns a configuration which passes the validation.  It is the
	// same as the result of normalizing an empty configuration, but with the
	// forwarding enabled.
	valid := func() (conf SyslogConfig) {
		return SyslogConfig{
			Enabled:  true,
			Network:  SyslogNetworkUDP,
			Address:  "192.0.2.1:514",
			Format:   SyslogFormatRFC5424,
			Tag:      DefaultSyslogTag,
			Hostname: testSyslogHostname,
			Facility: DefaultSyslogFacility,
		}
	}

	testCases := []struct {
		// modify changes a valid configuration to make it invalid.
		modify  func(conf *SyslogConfig)
		name    string
		wantErr string
	}{{
		name: "valid",
	}, {
		name:   "valid_tcp",
		modify: func(conf *SyslogConfig) { conf.Network = SyslogNetworkTCP },
	}, {
		name:   "valid_no_hostname",
		modify: func(conf *SyslogConfig) { conf.Hostname = "" },
	}, {
		name:   "valid_disabled",
		modify: func(conf *SyslogConfig) { conf.Enabled = false },
	}, {
		name:    "addr_is_empty",
		wantErr: "address is empty",
		modify:  func(conf *SyslogConfig) { conf.Address = "" },
	}, {
		name:    "addr_is_invalid",
		wantErr: "invalid address",
		modify:  func(conf *SyslogConfig) { conf.Address = "192.0.2.1" },
	}, {
		name:    "network_is_invalid",
		wantErr: "invalid network",
		modify:  func(conf *SyslogConfig) { conf.Network = "sctp" },
	}, {
		name:    "format_is_invalid",
		wantErr: "invalid format",
		modify:  func(conf *SyslogConfig) { conf.Format = "rfc9999" },
	}, {
		name:    "facility_is_negative",
		wantErr: "invalid facility",
		modify:  func(conf *SyslogConfig) { conf.Facility = -1 },
	}, {
		name:    "facility_is_too_big",
		wantErr: "invalid facility",
		modify:  func(conf *SyslogConfig) { conf.Facility = 24 },
	}, {
		name:    "hostname_is_invalid",
		wantErr: "invalid hostname",
		modify:  func(conf *SyslogConfig) { conf.Hostname = "invalid hostname" },
	}, {
		name:    "tag_is_empty",
		wantErr: "tag is empty",
		modify:  func(conf *SyslogConfig) { conf.Tag = "" },
	}, {
		name:    "tag_contains_space",
		wantErr: "invalid character in tag",
		modify:  func(conf *SyslogConfig) { conf.Tag = "AdGuard Home" },
	}, {
		name:    "tag_is_too_long",
		wantErr: "tag is too long",
		modify:  func(conf *SyslogConfig) { conf.Tag = strings.Repeat("a", maxSyslogTagLen+1) },
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := valid()
			if tc.modify != nil {
				tc.modify(&conf)
			}

			err := conf.validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestSyslogFormatter(t *testing.T) {
	conf := testSyslogConfig(SyslogNetworkUDP, "192.0.2.1:514")
	entry := testSyslogEntry()

	// The priority value is the facility multiplied by eight plus the
	// severity, which is always info for the query log.  local0 is 16, info is
	// 6, so the expected value is 134.
	t.Run("rfc5424", func(t *testing.T) {
		conf.Format = SyslogFormatRFC5424

		msg := string(newSyslogFormatter(conf, testSyslogHostname).format(entry))

		require.True(
			t,
			strings.HasPrefix(msg, "<134>1 2026-09-10T12:34:56.789Z test-host AdGuardHome - - - {"),
			"got %q",
			msg,
		)

		requireSyslogPayload(t, msg)
	})

	t.Run("rfc3164", func(t *testing.T) {
		conf.Format = SyslogFormatRFC3164

		msg := string(newSyslogFormatter(conf, testSyslogHostname).format(entry))

		require.True(
			t,
			strings.HasPrefix(msg, "<134>Sep 10 12:34:56 test-host AdGuardHome["),
			"got %q",
			msg,
		)

		requireSyslogPayload(t, msg)
	})

	t.Run("nil_hostname", func(t *testing.T) {
		conf.Format = SyslogFormatRFC5424

		// An unresolvable hostname results in the NILVALUE placeholder.
		msg := string(newSyslogFormatter(conf, syslogNilValue).format(entry))

		require.True(t, strings.HasPrefix(msg, "<134>1 2026-09-10T12:34:56.789Z - "), "got %q", msg)
	})
}

func TestResolveSyslogHostname(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		assert.Equal(t, testSyslogHostname, resolveSyslogHostname(testSyslogHostname))
	})

	t.Run("system", func(t *testing.T) {
		// The actual value depends on the machine, so only check that it is
		// never empty.
		assert.NotEmpty(t, resolveSyslogHostname(""))
	})
}

func TestSyslogSender_enqueue_drop(t *testing.T) {
	s := newSyslogSender(testLogger, func() (conf SyslogConfig) {
		return SyslogConfig{}
	})

	entry := testSyslogEntry()

	for range syslogQueueSize {
		s.enqueue(entry)
	}

	require.Equal(t, uint64(0), s.dropped.Load())

	// The queue is full, so the next enqueue must neither block nor panic.
	done := make(chan struct{})
	go func() {
		s.enqueue(entry)
		close(done)
	}()

	select {
	case <-done:
		// Go on.
	case <-time.After(syslogTestTimeout):
		require.FailNow(t, "enqueue blocked on a full queue")
	}

	assert.Equal(t, uint64(1), s.dropped.Load())
}

func TestSyslogSender_udp(t *testing.T) {
	pc, err := net.ListenPacket(SyslogNetworkUDP, "127.0.0.1:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, pc.Close)

	l := newSyslogTestQueryLog(t, testSyslogConfig(SyslogNetworkUDP, pc.LocalAddr().String()))

	addTestEntry(l, "ads.example.org", testAnswerIPv4, testClientIPv4, filtering.FilteredBlockList)

	require.NoError(t, pc.SetReadDeadline(time.Now().Add(syslogTestTimeout)))

	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)

	msg := string(buf[:n])
	require.True(t, strings.HasPrefix(msg, "<134>1 "), "got %q", msg)
	assert.Contains(t, msg, testSyslogHostname+" "+DefaultSyslogTag)

	requireSyslogPayload(t, msg)
}

func TestSyslogSender_tcp(t *testing.T) {
	ln, err := net.Listen(SyslogNetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, ln.Close)

	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, aErr := ln.Accept()
		if aErr != nil {
			errCh <- aErr

			return
		}

		connCh <- conn
	}()

	l := newSyslogTestQueryLog(t, testSyslogConfig(SyslogNetworkTCP, ln.Addr().String()))

	addTestEntry(l, "ads.example.org", testAnswerIPv4, testClientIPv4, filtering.FilteredBlockList)

	conn := waitForConn(t, connCh, errCh)
	testutil.CleanupAndRequireSuccess(t, conn.Close)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(syslogTestTimeout)))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)

	msg := string(buf[:n])
	require.True(t, strings.HasPrefix(msg, "<134>1 "), "got %q", msg)
	assert.Contains(t, msg, testSyslogHostname+" "+DefaultSyslogTag)

	requireSyslogPayload(t, msg)
}

// waitForConn waits for a connection from connCh or an error from errCh.
func waitForConn(t *testing.T, connCh <-chan net.Conn, errCh <-chan error) (conn net.Conn) {
	t.Helper()

	select {
	case conn = <-connCh:
		return conn
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(syslogTestTimeout):
		require.FailNow(t, "timeout waiting for the connection")
	}

	return nil
}
