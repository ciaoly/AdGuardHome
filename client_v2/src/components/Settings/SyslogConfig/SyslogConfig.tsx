import { createEffect, createMemo, createSignal, on } from 'solid-js';

import { ConfigDialog } from 'panel/common/ui/ConfigDialog';
import intl from 'panel/common/intl';
import { setLogsConfig, queryLogsState } from 'panel/stores/queryLogs';
import { addSuccessToast } from 'panel/stores/toasts';

import {
    buildQueryLogConfig,
    normalizeSyslogConfig,
    validateSyslogAddress,
    type SyslogConfig as SyslogConfigType,
} from '../helpers';

import { Form } from './Form';

type Props = {
    config: SyslogConfigType;
    processing: boolean;
    modalOpen: boolean;
    onModalClose: () => void;
};

export const SyslogConfig = (props: Props) => {
    const [values, setValues] = createSignal<SyslogConfigType>(normalizeSyslogConfig(props.config));
    const [submitted, setSubmitted] = createSignal(false);

    createEffect(
        on(
            () => props.modalOpen,
            (open) => {
                if (!open) return;

                setSubmitted(false);
                setValues(normalizeSyslogConfig(props.config));
            },
        ),
    );

    // The error is only shown after a failed save attempt, not while the user
    // is still typing the address.
    const addressError = createMemo(() => {
        if (!submitted()) return undefined;

        return validateSyslogAddress(values());
    });

    const handleChange = (patch: Partial<SyslogConfigType>) => {
        setSubmitted(false);
        setValues((prev) => ({ ...prev, ...patch }));
    };

    const handleSave = () => {
        setSubmitted(true);

        const config = values();
        if (validateSyslogAddress(config)) {
            return;
        }

        setLogsConfig(buildQueryLogConfig(queryLogsState, { syslog: config }));
        addSuccessToast(intl.getMessage('changes_saved_success'));
        props.onModalClose();
    };

    return (
        <ConfigDialog
            open={props.modalOpen}
            title={intl.getMessage('settings_syslog_title')}
            onClose={props.onModalClose}
            onSubmit={handleSave}
            processing={props.processing}
        >
            <Form
                values={values()}
                onChange={handleChange}
                processing={props.processing}
                addressError={addressError()}
            />
        </ConfigDialog>
    );
};
