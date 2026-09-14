import { describe, it, expect } from 'vitest';

import {
    buildQueryLogConfig,
    buildStatsConfig,
    normalizeSyslogConfig,
    validateSyslogAddress,
    DEFAULT_SYSLOG_CONFIG,
    type QueryLogConfig,
    type StatsConfig,
} from 'panel/components/Settings/helpers';

describe('buildQueryLogConfig', () => {
    it('returns only the six config fields', () => {
        const state: QueryLogConfig & Record<string, unknown> = {
            enabled: true,
            anonymize_client_ip: false,
            interval: 86400000,
            ignored: ['example.org'],
            ignored_enabled: true,
            syslog: DEFAULT_SYSLOG_CONFIG,
            // runtime fields that must NOT appear in the result
            processingGetLogs: true,
            processingClear: false,
            processingGetConfig: false,
            processingSetConfig: false,
            processingAdditionalLogs: false,
            logs: [] as unknown[],
            oldest: '',
            filter: {} as Record<string, unknown>,
            isFiltered: false,
            isDetailed: true,
            isEntireLog: false,
            customInterval: null as null,
        };
        const result = buildQueryLogConfig(state);
        expect(result).toEqual({
            enabled: true,
            anonymize_client_ip: false,
            interval: 86400000,
            ignored: ['example.org'],
            ignored_enabled: true,
            syslog: DEFAULT_SYSLOG_CONFIG,
        });
    });

    it('applies overrides on top of the store values', () => {
        const state: QueryLogConfig = {
            enabled: true,
            anonymize_client_ip: false,
            interval: 86400000,
            ignored: [],
            ignored_enabled: false,
            syslog: DEFAULT_SYSLOG_CONFIG,
        };
        const result = buildQueryLogConfig(state, {
            enabled: false,
            ignored: ['a', 'b'],
        });
        expect(result).toEqual({
            enabled: false,
            anonymize_client_ip: false,
            interval: 86400000,
            ignored: ['a', 'b'],
            ignored_enabled: false,
            syslog: DEFAULT_SYSLOG_CONFIG,
        });
    });
});

describe('normalizeSyslogConfig', () => {
    it('returns the defaults for an undefined config', () => {
        expect(normalizeSyslogConfig(undefined)).toEqual(DEFAULT_SYSLOG_CONFIG);
    });

    it('keeps the received values and fills in the missing ones', () => {
        const result = normalizeSyslogConfig({ enabled: true, address: '192.0.2.1:514' });

        expect(result.enabled).toBe(true);
        expect(result.address).toBe('192.0.2.1:514');
        expect(result.network).toBe(DEFAULT_SYSLOG_CONFIG.network);
        expect(result.format).toBe(DEFAULT_SYSLOG_CONFIG.format);
        expect(result.facility).toBe(DEFAULT_SYSLOG_CONFIG.facility);
    });
});

describe('validateSyslogAddress', () => {
    const valid = { ...DEFAULT_SYSLOG_CONFIG, enabled: true, address: '192.0.2.1:514' };

    it('accepts a valid address', () => {
        expect(validateSyslogAddress(valid)).toBeUndefined();
        expect(validateSyslogAddress({ ...valid, address: 'siem.example:1514' })).toBeUndefined();
        expect(validateSyslogAddress({ ...valid, address: '[::1]:514' })).toBeUndefined();
    });

    it('ignores an invalid address when the forwarding is disabled', () => {
        expect(validateSyslogAddress({ ...valid, enabled: false, address: '' })).toBeUndefined();
    });

    it('requires an address when the forwarding is enabled', () => {
        expect(validateSyslogAddress({ ...valid, address: '' })).toBeDefined();
        expect(validateSyslogAddress({ ...valid, address: '   ' })).toBeDefined();
    });

    it('rejects an address without a port', () => {
        expect(validateSyslogAddress({ ...valid, address: '192.0.2.1' })).toBeDefined();
    });
});

describe('buildStatsConfig', () => {
    it('returns only the four config fields', () => {
        const state: StatsConfig & Record<string, unknown> = {
            enabled: true,
            interval: 86400000,
            ignored: [],
            ignored_enabled: false,
            processingGetConfig: false,
            processingSetConfig: false,
            processingStats: false,
            processingReset: false,
            customInterval: null as null,
            dnsQueries: [] as unknown[],
            topClients: [] as unknown[],
            avgProcessingTime: 0,
        };
        const result = buildStatsConfig(state);
        expect(result).toEqual({
            enabled: true,
            interval: 86400000,
            ignored: [],
            ignored_enabled: false,
        });
    });

    it('applies overrides', () => {
        const state = {
            enabled: true,
            interval: 86400000,
            ignored: ['x'],
            ignored_enabled: true,
        };
        const result = buildStatsConfig(state, { enabled: false });
        expect(result.enabled).toBe(false);
        expect(result.interval).toBe(86400000);
    });
});
