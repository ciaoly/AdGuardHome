import type { SyslogConfigFormat } from './syslogConfigFormat';
import type { SyslogConfigNetwork } from './syslogConfigNetwork';

/**
 * Configuration for forwarding query log entries to a remote syslog server.  The forwarding is independent of the local query log storage, so it is possible to forward the entries without writing them to disk.
 */
export interface SyslogConfig {
    /** If true, the query log entries are forwarded to the syslog server. */
    enabled: boolean;
    /** Transport protocol used to reach the syslog server */
    network?: SyslogConfigNetwork;
    /** Host and port of the syslog server, for example "192.0.2.1:514" */
    address?: string;
    /** Format of the syslog message.  RFC 5424 is the modern standard and should be preferred, RFC 3164 is provided for legacy collectors. */
    format?: SyslogConfigFormat;
    /** APP-NAME field of the syslog message */
    tag?: string;
    /** HOSTNAME field of the syslog message.  If empty, the host name of the machine is used. */
    hostname?: string;
    /**
     * Syslog facility, from 0 to 23
     * @minimum 0
     * @maximum 23
     */
    facility?: number;
}
