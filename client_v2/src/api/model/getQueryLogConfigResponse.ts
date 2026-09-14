import type { SyslogConfig } from './syslogConfig';

/**
 * Query log configuration
 */
export interface GetQueryLogConfigResponse {
    /** Is query log enabled */
    enabled: boolean;
    /** Time period for query log rotation in milliseconds. */
    interval: number;
    /** Anonymize clients' IP addresses */
    anonymize_client_ip: boolean;
    /** List of host names, which should not be written to log */
    ignored: string[];
    /** If true, the host names in the `ignored` array are excluded from the query log. */
    ignored_enabled?: boolean;
    /** Configuration for forwarding query log entries to a remote syslog server. The forwarding is independent of the local query log storage, so it is possible to forward the entries without writing them to disk. */
    syslog?: SyslogConfig;
}
