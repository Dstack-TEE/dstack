import { getOpenApiTitleAndDescription, optionallyAddLeadingSlash, slugToTitle, isAllowedLocalSchemaUrl, buildOpenApiMetaTag, } from '@mintlify/common';
import { outputFile } from 'fs-extra';
import fse from 'fs-extra';
import fs from 'fs/promises';
import yaml from 'js-yaml';
import { OpenAPIV3 } from 'openapi-types';
import path, { join, parse, resolve } from 'path';
import { prepareStringToBeValidFilename, generateUniqueFilenameWithoutExtension, } from '../apiPages/common.js';
import { fetchOpenApi } from '../utils/network.js';
export const getOpenApiDefinition = async (pathOrDocumentOrUrl, localSchema) => {
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
                const file = await fs.readFile(pathname, 'utf-8');
                pathOrDocumentOrUrl = yaml.load(file);
            }
        }
    }
    const isUrl = pathOrDocumentOrUrl instanceof URL;
    if (pathOrDocumentOrUrl instanceof URL) {
        if (!isAllowedLocalSchemaUrl(pathOrDocumentOrUrl.toString(), localSchema)) {
            throw new Error('Only HTTPS URLs are supported. HTTP URLs are only supported with the cli option --local-schema.');
        }
        pathOrDocumentOrUrl = await fetchOpenApi(pathOrDocumentOrUrl);
    }
    return { document: pathOrDocumentOrUrl, isUrl };
};
export const createOpenApiFrontmatter = async ({ filename, openApiMetaTag, version, deprecated, }) => {
    const data = `---
openapi: ${openApiMetaTag}${version ? `\nversion: ${version}` : ''}${deprecated ? `\ndeprecated: ${deprecated}` : ''}
---`;
    await outputFile(filename, data);
};
const isHiddenOperation = (operation) => {
    return operation['x-hidden'];
};
const isExcludedOperation = (operation) => {
    return operation['x-excluded'];
};
export function processOpenApiPath(path, pathItemObject, schema, nav, decoratedNav, writePromises, pagesAcc, options, 
// eslint-disable-next-line @typescript-eslint/no-explicit-any
findNavGroup) {
    const openApiFilePathFromRoot = options.openApiFilePath
        ? optionallyAddLeadingSlash(options.openApiFilePath)
        : undefined;
    Object.values(OpenAPIV3.HttpMethods).forEach((method) => {
        if (method in pathItemObject) {
            const operation = pathItemObject[method];
            if (isExcludedOperation(operation)) {
                return;
            }
            const groupName = operation?.tags?.[0];
            const title = prepareStringToBeValidFilename(operation?.summary) ??
                `${method}-${prepareStringToBeValidFilename(path)}`;
            const folder = prepareStringToBeValidFilename(groupName) ?? '';
            const base = join(options.outDir ?? '', folder, title);
            const navGroup = findNavGroup(nav, groupName);
            const decoratedNavGroup = findNavGroup(decoratedNav, groupName);
            const filenameWithoutExtension = generateUniqueFilenameWithoutExtension(navGroup, base);
            const openapiMetaTag = buildOpenApiMetaTag({
                filePath: openApiFilePathFromRoot,
                method,
                path,
            });
            const { title: titleTag, description } = getOpenApiTitleAndDescription([
                {
                    filename: options.openApiFilePath
                        ? parse(options.openApiFilePath).name
                        : 'filler-filename',
                    spec: schema,
                    originalFileLocation: options.openApiFilePath,
                },
            ], openapiMetaTag);
            const page = {
                openapi: openapiMetaTag,
                href: resolve('/', filenameWithoutExtension),
                title: titleTag ?? slugToTitle(filenameWithoutExtension),
                description,
                deprecated: operation?.deprecated,
                version: options.version,
            };
            if (!isHiddenOperation(operation)) {
                navGroup.push(filenameWithoutExtension);
                decoratedNavGroup.push(page);
            }
            pagesAcc[filenameWithoutExtension] = page;
            const targetPath = options.outDirBasePath
                ? join(options.outDirBasePath, `${filenameWithoutExtension}.mdx`)
                : `${filenameWithoutExtension}.mdx`;
            if (options.writeFiles && (!fse.pathExistsSync(targetPath) || options.overwrite)) {
                writePromises.push(createOpenApiFrontmatter({
                    filename: targetPath,
                    openApiMetaTag: openapiMetaTag,
                    version: options.version,
                    deprecated: operation?.deprecated,
                }));
            }
        }
    });
}
export function processOpenApiWebhook(webhook, webhookObject, _schema, nav, decoratedNav, writePromises, pagesAcc, options, 
// eslint-disable-next-line @typescript-eslint/no-explicit-any
findNavGroup) {
    const openApiFilePathFromRoot = options.openApiFilePath
        ? optionallyAddLeadingSlash(options.openApiFilePath)
        : undefined;
    Object.values(OpenAPIV3.HttpMethods).forEach((method) => {
        if (method in webhookObject) {
            const operation = webhookObject[method];
            if (isExcludedOperation(operation)) {
                return;
            }
            const groupName = operation?.tags?.[0];
            const title = prepareStringToBeValidFilename(operation?.summary) ??
                `${prepareStringToBeValidFilename(webhook)}`;
            const folder = prepareStringToBeValidFilename(groupName) ?? '';
            const base = join(options.outDir ?? '', folder, title);
            const navGroup = findNavGroup(nav, groupName);
            const decoratedNavGroup = findNavGroup(decoratedNav, groupName);
            const filenameWithoutExtension = generateUniqueFilenameWithoutExtension(navGroup, base);
            const openapiMetaTag = buildOpenApiMetaTag({
                filePath: openApiFilePathFromRoot,
                method: 'webhook',
                path: webhook,
            });
            const description = operation?.description;
            const page = {
                openapi: openapiMetaTag,
                href: resolve('/', filenameWithoutExtension),
                title: slugToTitle(filenameWithoutExtension),
                description,
                version: options.version,
                deprecated: operation?.deprecated,
            };
            if (!isHiddenOperation(operation)) {
                navGroup.push(filenameWithoutExtension);
                decoratedNavGroup.push(page);
            }
            pagesAcc[filenameWithoutExtension] = page;
            const targetPath = options.outDirBasePath
                ? join(options.outDirBasePath, `${filenameWithoutExtension}.mdx`)
                : `${filenameWithoutExtension}.mdx`;
            if (options.writeFiles && (!fse.pathExistsSync(targetPath) || options.overwrite)) {
                writePromises.push(createOpenApiFrontmatter({
                    filename: targetPath,
                    openApiMetaTag: openapiMetaTag,
                    version: options.version,
                    deprecated: operation?.deprecated,
                }));
            }
        }
    });
}
//# sourceMappingURL=common.js.map