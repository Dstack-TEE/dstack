import { validateAsyncApi, isAllowedLocalSchemaUrl, } from '@mintlify/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fetchAsyncApi } from '../utils/network.js';
export const getAsyncApiDefinition = async (pathOrDocumentOrUrl, localSchema) => {
    let document = undefined;
    if (typeof pathOrDocumentOrUrl === 'string') {
        if (pathOrDocumentOrUrl.startsWith('http:') && !localSchema) {
            // This is an invalid location either for a file or a URL
            throw new Error('Only HTTPS URLs are supported. HTTP URLs are only supported with the cli option --local-schema.');
        }
        else {
            try {
                const url = new URL(pathOrDocumentOrUrl);
                pathOrDocumentOrUrl = url;
            }
            catch {
                const pathname = path.join(process.cwd(), pathOrDocumentOrUrl.toString());
                try {
                    const file = await fs.readFile(pathname, 'utf-8');
                    const { document: asyncApiDocument, errorMessage } = await validateAsyncApi(file);
                    if (!asyncApiDocument) {
                        throw new Error(`${pathname} - this document is not a valid AsyncAPI document - ${errorMessage}`);
                    }
                    document = asyncApiDocument;
                }
                catch (error) {
                    throw new Error(`Failed to read file ${pathname} - ${error}`);
                }
            }
        }
    }
    const isUrl = pathOrDocumentOrUrl instanceof URL;
    if (pathOrDocumentOrUrl instanceof URL) {
        if (!isAllowedLocalSchemaUrl(pathOrDocumentOrUrl.toString(), localSchema)) {
            throw new Error('Only HTTPS URLs are supported. HTTP URLs are only supported with the cli option --local-schema.');
        }
        document = await fetchAsyncApi(pathOrDocumentOrUrl);
    }
    return { document, isUrl };
};
//# sourceMappingURL=getAsyncApiDefinition.js.map