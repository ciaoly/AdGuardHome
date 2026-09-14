import { Show } from 'solid-js';

import intl from 'panel/common/intl';
import { Input } from 'panel/common/controls/Input';
import { Select } from 'panel/common/controls/Select';
import { SwitchGroup } from 'panel/common/ui/SettingsGroup';
import theme from 'panel/lib/theme';
import type { IOption } from 'panel/lib/helpers/utils';

import type { SyslogConfig, SyslogFormat, SyslogNetwork } from '../helpers';

import s from './SyslogConfig.module.pcss';

const NETWORK_OPTIONS: IOption<SyslogNetwork>[] = [
    { value: 'udp', label: 'UDP' },
    { value: 'tcp', label: 'TCP' },
];

const FORMAT_OPTIONS: IOption<SyslogFormat>[] = [
    { value: 'rfc5424', label: 'RFC 5424' },
    { value: 'rfc3164', label: 'RFC 3164' },
];

/**
 * All syslog facilities, so that an unusual value coming from the config file
 * is still shown correctly.
 */
const FACILITY_OPTIONS: IOption<number>[] = [
    { value: 0, label: 'kern' },
    { value: 1, label: 'user' },
    { value: 2, label: 'mail' },
    { value: 3, label: 'daemon' },
    { value: 4, label: 'auth' },
    { value: 5, label: 'syslog' },
    { value: 6, label: 'lpr' },
    { value: 7, label: 'news' },
    { value: 8, label: 'uucp' },
    { value: 9, label: 'cron' },
    { value: 10, label: 'authpriv' },
    { value: 11, label: 'ftp' },
    { value: 12, label: 'ntp' },
    { value: 13, label: 'security' },
    { value: 14, label: 'console' },
    { value: 15, label: 'solaris-cron' },
    { value: 16, label: 'local0' },
    { value: 17, label: 'local1' },
    { value: 18, label: 'local2' },
    { value: 19, label: 'local3' },
    { value: 20, label: 'local4' },
    { value: 21, label: 'local5' },
    { value: 22, label: 'local6' },
    { value: 23, label: 'local7' },
];

type Props = {
    values: SyslogConfig;
    onChange: (patch: Partial<SyslogConfig>) => void;
    processing: boolean;
    addressError?: string;
};

export const Form = (props: Props) => {
    const optionOf = <T,>(options: IOption<T>[], value: T) =>
        options.find((opt) => opt.value === value) ?? options[0];

    const inputValue = (e: Event) => (e.target as HTMLInputElement).value;
    const switchValue = (e: Event) => (e.currentTarget as HTMLInputElement).checked;

    return (
        <div class={s.form}>
            <SwitchGroup
                id="syslog-enabled"
                title={intl.getMessage('settings_syslog_enabled')}
                description={intl.getMessage('settings_syslog_enabled_desc')}
                checked={props.values.enabled}
                disabled={props.processing}
                onChange={(e) => props.onChange({ enabled: switchValue(e) })}
            />

            <Show when={props.values.enabled}>
                <div class={s.field}>
                    <label class={theme.text.t3} for="syslog-address">
                        {intl.getMessage('settings_syslog_address')}
                    </label>
                    <Input
                        id="syslog-address"
                        placeholder="192.0.2.1:514"
                        value={props.values.address}
                        disabled={props.processing}
                        error={!!props.addressError}
                        errorMessage={props.addressError}
                        size="large"
                        onChange={(e) => props.onChange({ address: inputValue(e) })}
                    />
                </div>

                <div class={s.field}>
                    <label class={theme.text.t3} for="syslog-network">
                        {intl.getMessage('settings_syslog_network')}
                    </label>
                    <Select
                        inputId="syslog-network"
                        options={NETWORK_OPTIONS}
                        value={optionOf(NETWORK_OPTIONS, props.values.network)}
                        onChange={(opt) => props.onChange({ network: opt.value })}
                        isDisabled={props.processing}
                        isSearchable={false}
                        size="responsive"
                        height="big"
                    />
                </div>

                <div class={s.field}>
                    <label class={theme.text.t3} for="syslog-format">
                        {intl.getMessage('settings_syslog_format')}
                    </label>
                    <Select
                        inputId="syslog-format"
                        options={FORMAT_OPTIONS}
                        value={optionOf(FORMAT_OPTIONS, props.values.format)}
                        onChange={(opt) => props.onChange({ format: opt.value })}
                        isDisabled={props.processing}
                        isSearchable={false}
                        size="responsive"
                        height="big"
                    />
                </div>

                <div class={s.field}>
                    <label class={theme.text.t3} for="syslog-facility">
                        {intl.getMessage('settings_syslog_facility')}
                    </label>
                    <Select
                        inputId="syslog-facility"
                        options={FACILITY_OPTIONS}
                        value={optionOf(FACILITY_OPTIONS, props.values.facility)}
                        onChange={(opt) => props.onChange({ facility: opt.value })}
                        isDisabled={props.processing}
                        isSearchable
                        size="responsive"
                        height="big"
                    />
                </div>

                <div class={s.field}>
                    <label class={theme.text.t3} for="syslog-tag">
                        {intl.getMessage('settings_syslog_tag')}
                    </label>
                    <Input
                        id="syslog-tag"
                        placeholder="AdGuardHome"
                        value={props.values.tag}
                        disabled={props.processing}
                        size="large"
                        onChange={(e) => props.onChange({ tag: inputValue(e) })}
                    />
                </div>

                <div class={s.field}>
                    <label class={theme.text.t3} for="syslog-hostname">
                        {intl.getMessage('settings_syslog_hostname')}
                    </label>
                    <Input
                        id="syslog-hostname"
                        placeholder={intl.getMessage('settings_syslog_hostname_placeholder')}
                        value={props.values.hostname}
                        disabled={props.processing}
                        size="large"
                        onChange={(e) => props.onChange({ hostname: inputValue(e) })}
                    />
                    <div class={theme.text.t3}>
                        {intl.getMessage('settings_syslog_hostname_desc')}
                    </div>
                </div>
            </Show>
        </div>
    );
};
