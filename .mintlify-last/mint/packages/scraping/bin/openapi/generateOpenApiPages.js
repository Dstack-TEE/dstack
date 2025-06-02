import { validate } from '@mintlify/common';
import { DEFAULT_API_GROUP_NAME } from '../apiPages/common.js';
import { getOpenApiDefinition, processOpenApiPath, processOpenApiWebhook, } from './common.js';
export async function generateOpenApiPages(pathOrDocumentOrUrl, opts) {
    const { document, isUrl } = await getOpenApiDefinition(pathOrDocumentOrUrl, opts?.localSchema);
    const { schema } = await validate(document);
    if (schema?.openapi === '3.0.0' &&
        (schema.paths === undefined || Object.keys(schema.paths).length === 0)) {
        throw new Error('No paths defined.');
    }
    else if (schema?.openapi === '3.1.0' &&
        (schema.paths === undefined || Object.keys(schema.paths).length === 0) &&
        (schema.webhooks === undefined || Object.keys(schema.webhooks).length === 0)) {
        throw new Error('No paths or webhooks defined.');
    }
    const nav = [];
    const decoratedNav = [];
    const writePromises = [];
    const pagesAcc = {};
    if (schema?.paths) {
        Object.entries(schema.paths).forEach(([path, pathItemObject]) => {
            if (!pathItemObject || typeof pathItemObject !== 'object') {
                return;
            }
            processOpenApiPath(path, pathItemObject, schema, nav, decoratedNav, writePromises, pagesAcc, opts ?? {}, findNavGroup);
        });
    }
    if (schema?.webhooks) {
        Object.entries(schema.webhooks).forEach(([webhook, webhookObject]) => {
            if (!webhookObject || typeof webhookObject !== 'object') {
                return;
            }
            processOpenApiWebhook(webhook, webhookObject, schema, nav, decoratedNav, writePromises, pagesAcc, opts ?? {}, findNavGroup);
        });
    }
    await Promise.all(writePromises);
    return {
        nav,
        decoratedNav,
        spec: schema,
        pagesAcc,
        isUrl,
    };
}
const findNavGroup = (nav, groupName = DEFAULT_API_GROUP_NAME) => {
    const group = nav.find((fileOrGroup) => typeof fileOrGroup === 'object' && 'group' in fileOrGroup && fileOrGroup.group === groupName);
    if (group === undefined) {
        const newGroup = {
            group: groupName,
            pages: [],
        };
        nav.push(newGroup);
        return newGroup.pages;
    }
    else {
        return group.pages;
    }
};
//# sourceMappingURL=generateOpenApiPages.js.map