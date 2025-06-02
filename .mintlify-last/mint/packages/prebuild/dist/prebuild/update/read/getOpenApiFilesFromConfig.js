import { getOpenApiDocumentFromUrl, isAllowedLocalSchemaUrl } from '@mintlify/common';
export const getOpenApiFilesFromConfig = async (type, config, localSchema) => {
    let openapi;
    if (type === 'docs') {
        openapi = config.api?.openapi;
    }
    else {
        openapi = config.openapi;
    }
    const openApiFiles = [];
    // Download OpenApi file if url is provided
    async function addOpenApiFileFromUrl(openapi) {
        const specFromUrl = await getOpenApiDocumentFromUrl(openapi);
        openApiFiles.push({
            filename: openapi,
            spec: specFromUrl,
            originalFileLocation: openapi,
        });
    }
    if (openapi) {
        if (typeof openapi === 'string' && isAllowedLocalSchemaUrl(openapi, localSchema)) {
            await addOpenApiFileFromUrl(openapi);
        }
        else if (typeof openapi === 'object' &&
            'source' in openapi &&
            isAllowedLocalSchemaUrl(openapi.source, localSchema)) {
            await addOpenApiFileFromUrl(openapi.source);
        }
    }
    return openApiFiles;
};
