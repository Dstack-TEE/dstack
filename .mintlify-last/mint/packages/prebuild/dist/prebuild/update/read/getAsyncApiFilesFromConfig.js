import { getAsyncApiDocumentFromUrl, isAllowedLocalSchemaUrl, } from '@mintlify/common';
export const getAsyncApiFilesFromConfig = async (config, localSchema) => {
    const asyncApiConfig = config.api?.asyncapi;
    const asyncApiFiles = [];
    async function addAsyncApiFileFromUrl(url) {
        try {
            const document = await getAsyncApiDocumentFromUrl(url);
            asyncApiFiles.push({
                filename: url,
                spec: document,
                originalFileLocation: url,
            });
        }
        catch (err) {
            console.error(err);
            throw err;
        }
    }
    if (asyncApiConfig) {
        if (typeof asyncApiConfig === 'string' &&
            isAllowedLocalSchemaUrl(asyncApiConfig, localSchema)) {
            await addAsyncApiFileFromUrl(asyncApiConfig);
        }
        else if (typeof asyncApiConfig === 'object' &&
            'source' in asyncApiConfig &&
            isAllowedLocalSchemaUrl(asyncApiConfig.source, localSchema)) {
            await addAsyncApiFileFromUrl(asyncApiConfig.source);
        }
    }
    return asyncApiFiles;
};
