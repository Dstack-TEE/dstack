import { validateAsyncApi } from '@mintlify/common';
import { findNavGroup } from '../apiPages/common.js';
import { getAsyncApiDefinition } from './getAsyncApiDefinition.js';
import { processAsyncApiChannel } from './processAsyncApiChannel.js';
export async function generateAsyncApiPagesForDocsConfig(spec, opts) {
    let document = undefined;
    let isUrl;
    if (typeof spec === 'string' || spec instanceof URL) {
        const { document: asyncApiDocument, isUrl: isUrlFromDefinition } = await getAsyncApiDefinition(spec, opts?.localSchema);
        if (asyncApiDocument) {
            document = asyncApiDocument;
        }
        isUrl = isUrlFromDefinition;
    }
    else {
        const { valid, errorMessage, document: asyncApiDocument } = await validateAsyncApi(spec);
        if (!valid && errorMessage) {
            throw new Error(errorMessage);
        }
        document = asyncApiDocument;
        isUrl = false;
    }
    if (!document) {
        throw new Error('No document defined');
    }
    const channels = document.channels();
    if (channels.isEmpty()) {
        throw new Error('No channels defined');
    }
    const nav = [];
    const decoratedNav = [];
    const writePromises = [];
    const pagesAcc = {};
    channels.all().forEach((channel) => {
        processAsyncApiChannel({
            channel: channel,
            nav,
            decoratedNav,
            writePromises,
            pagesAcc,
            opts,
            findNavGroup,
        });
    });
    await Promise.all(writePromises);
    return {
        nav,
        decoratedNav,
        spec: document,
        pagesAcc,
        isUrl,
    };
}
//# sourceMappingURL=generateAsyncApiPagesForDocsConfig.js.map