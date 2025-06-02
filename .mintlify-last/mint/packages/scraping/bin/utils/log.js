export const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    grey: '\x1b[90m',
    default: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    italic: '\x1b[3m',
};
const noColors = {
    red: '',
    green: '',
    yellow: '',
    blue: '',
    magenta: '',
    cyan: '',
    grey: '',
    default: '',
    bold: '',
    dim: '',
    italic: '',
};
const statuses = ['success', 'failure', 'error', 'warn', 'warning', 'info'];
export const activeColors = 'stdout' in process && 'hasColors' in process.stdout && process.stdout.hasColors()
    ? colors
    : noColors;
export const checkIcon = '✔ ';
export const xIcon = '✘ ';
export const infoIcon = 'ⓘ ';
export const warningIcon = '⚠ ';
export function log(message, statusOrColor = undefined, opts = {}) {
    let color = activeColors.blue;
    let statusMsg = 'INFO';
    let icon = infoIcon;
    const msg = typeof message === 'string' ? message.toLowerCase() : '';
    if (!statusOrColor) {
        statusOrColor =
            msg.includes('fail') ||
                msg.includes('error') ||
                msg.includes('could not') ||
                msg.includes("couldn't") ||
                msg.includes('did not') ||
                msg.includes('invalid') ||
                msg.includes("didn't")
                ? 'error'
                : msg.includes('success') ||
                    msg.includes('downloaded') ||
                    msg.includes('written') ||
                    msg.includes('added')
                    ? 'success'
                    : msg.includes('warn')
                        ? 'warn'
                        : undefined;
    }
    switch (statusOrColor) {
        case undefined:
        case 'info':
            break;
        case 'success':
            color = activeColors.green;
            statusMsg = 'SUCCESS';
            icon = checkIcon;
            break;
        case 'warn':
        case 'warning':
            color = activeColors.yellow;
            statusMsg = 'WARNING';
            icon = warningIcon;
            break;
        case 'failure':
        case 'error':
            color = activeColors.red;
            statusMsg = 'ERROR';
            icon = xIcon;
            break;
    }
    if (opts.omitIcon)
        icon = '';
    if (opts.omitStatusMessage)
        statusMsg = '';
    const separator = opts.omitStatusMessage ? '' : !opts.omitIcon ? ' - ' : '';
    if (opts.leadingNewLine)
        console.log();
    console[statusOrColor === 'error' || statusOrColor === 'failure'
        ? 'error'
        : statusOrColor === 'warn' || statusOrColor === 'warning'
            ? 'warn'
            : 'log'](`${color}${icon}${icon ? ' ' : ''}${statusMsg}${activeColors.default}${separator}${typeof message === 'string' ||
        typeof message === 'bigint' ||
        typeof message === 'number' ||
        typeof message === 'boolean'
        ? message
        : JSON.stringify(message, undefined, 2)}`);
    if (opts.trailingNewLine)
        console.log();
}
//# sourceMappingURL=log.js.map