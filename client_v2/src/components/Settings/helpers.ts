import intl from 'panel/common/intl';
import { HOUR, DAY, RETENTION_CUSTOM } from 'panel/helpers/constants';
import { captitalizeWords } from '../../helpers/helpers';

export const formatIntervalText = (intervalMs: number) => {
    if (intervalMs === 6 * HOUR) {
        return intl.getPlural('settings_hours', 6);
    }
    if (intervalMs === DAY) {
        return intl.getPlural('settings_hours', 24);
    }
    if (intervalMs % DAY === 0) {
        return intl.getPlural('settings_days', intervalMs / DAY);
    }
    return intl.getPlural('settings_hours', Math.floor(intervalMs / HOUR));
};

export const getIntervalTitle = (intervalMs: number) => {
    if (intervalMs === RETENTION_CUSTOM) {
        return intl.getMessage('settings_custom');
    }
    return formatIntervalText(intervalMs);
};

export const getDefaultInterval = (customInterval?: number, interval?: number) => {
    if (customInterval && customInterval > 0) {
        return RETENTION_CUSTOM;
    }
    return interval || DAY;
};

export const resolveInterval = (interval: number, customInterval?: number | null): number => {
    if (customInterval) {
        return customInterval >= HOUR ? customInterval : customInterval * HOUR;
    }

    return interval;
};

export const getRetentionSummary = (intervalMs: number) => {
    if (intervalMs === 6 * HOUR) {
        return intl.getPlural('last_hours', 6);
    }
    if (intervalMs === DAY) {
        return intl.getPlural('last_hours', 24);
    }
    if (intervalMs % DAY === 0) {
        return intl.getPlural('last_days', intervalMs / DAY);
    }
    return intl.getPlural('last_hours', Math.floor(intervalMs / HOUR));
};

const SAFESEARCH_TITLES = {
    bing: 'Bing',
    duckduckgo: 'DuckDuckGo',
    ecosia: 'Ecosia',
    google: 'Google',
    pixabay: 'Pixabay',
    yandex: 'Yandex',
    youtube: 'YouTube',
} as const;

export const getSafeSearchProviderTitle = (key: string) => {
    return SAFESEARCH_TITLES[key as keyof typeof SAFESEARCH_TITLES] ?? captitalizeWords(key);
};

export type SyslogConfig = {
    enabled: boolean;
    network: SyslogNetwork;
    address: string;
    format: SyslogFormat;
    tag: string;
    hostname: string;
    facility: number;
};

export type SyslogNetwork = 'udp' | 'tcp';

export type SyslogFormat = 'rfc5424' | 'rfc3164';

export const DEFAULT_SYSLOG_CONFIG: SyslogConfig = {
    enabled: false,
    network: 'udp',
    address: '',
    format: 'rfc5424',
    tag: 'AdGuardHome',
    hostname: '',
    facility: 16,
};

/**
 * Validates the syslog server address.  Returns an error message, or undefined
 * if the configuration is valid.  An address is only required when the
 * forwarding is enabled.  The backend performs the authoritative validation,
 * this is only a quick check to avoid an obviously failed request.
 */
export const validateSyslogAddress = (config: SyslogConfig): string | undefined => {
    if (!config.enabled) {
        return undefined;
    }

    const address = config.address.trim();
    if (!address) {
        return intl.getMessage('form_error_required');
    }

    // Either "host:port", "192.0.2.1:port", or "[::1]:port".
    if (!/^(?:\[[0-9a-fA-F:]+\]|[^\s:]+):\d{1,5}$/.test(address)) {
        return intl.getMessage('settings_syslog_address_error');
    }

    return undefined;
};

/**
 * Merges a partial syslog config received from the backend with the defaults,
 * so that every field is always defined.
 */
export const normalizeSyslogConfig = (config?: Partial<SyslogConfig>): SyslogConfig => ({
    enabled: config?.enabled ?? DEFAULT_SYSLOG_CONFIG.enabled,
    network: config?.network ?? DEFAULT_SYSLOG_CONFIG.network,
    address: config?.address ?? DEFAULT_SYSLOG_CONFIG.address,
    format: config?.format ?? DEFAULT_SYSLOG_CONFIG.format,
    tag: config?.tag ?? DEFAULT_SYSLOG_CONFIG.tag,
    hostname: config?.hostname ?? DEFAULT_SYSLOG_CONFIG.hostname,
    facility: config?.facility ?? DEFAULT_SYSLOG_CONFIG.facility,
});

export type QueryLogConfig = {
    enabled: boolean;
    anonymize_client_ip: boolean;
    interval: number;
    ignored: string[];
    ignored_enabled: boolean;
    syslog: SyslogConfig;
};

export type StatsConfig = {
    enabled: boolean;
    interval: number;
    ignored: string[];
    ignored_enabled: boolean;
};

/**
 * Builds a backend-ready query-log config payload from the queryLogs store
 * (or any object with the required fields), applying optional overrides.
 */
export const buildQueryLogConfig = (
    state: QueryLogConfig,
    overrides?: Partial<QueryLogConfig>,
): QueryLogConfig => ({
    enabled: state.enabled,
    anonymize_client_ip: state.anonymize_client_ip,
    interval: state.interval,
    ignored: state.ignored,
    ignored_enabled: state.ignored_enabled,
    syslog: state.syslog,
    ...overrides,
});

/**
 * Builds a backend-ready stats config payload from the stats store,
 * applying optional overrides. Strips runtime-only fields.
 */
export const buildStatsConfig = (
    state: StatsConfig,
    overrides?: Partial<StatsConfig>,
): StatsConfig => ({
    enabled: state.enabled,
    interval: state.interval,
    ignored: state.ignored,
    ignored_enabled: state.ignored_enabled,
    ...overrides,
});
