/**
 * Format of the syslog message. RFC 5424 is the modern standard and should be preferred, RFC 3164 is provided for legacy collectors.
 */
export type SyslogConfigFormat = 'rfc5424' | 'rfc3164';
