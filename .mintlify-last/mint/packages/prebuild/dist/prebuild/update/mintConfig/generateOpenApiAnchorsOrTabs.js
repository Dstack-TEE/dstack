import { getOpenApiDocumentFromUrl, isAllowedLocalSchemaUrl } from '@mintlify/common';
import { generateOpenApiPages } from '@mintlify/scraping';
import * as path from 'path';
import { getOpenApiFilesFromConfig } from '../read/getOpenApiFilesFromConfig.js';
export const generateOpenApiAnchorsOrTabs = async (mintConfig, openApiFiles, targetDir, localSchema) => {
    const openapiFilesFromMintConfig = await getOpenApiFilesFromConfig('mint', mintConfig);
    openApiFiles.push(...openapiFilesFromMintConfig);
    const pagesAcc = {};
    const [anchorOpenApiInfo, tabOpenApiInfo] = await Promise.all([
        generateOpenApiAnchorOrTab(mintConfig.anchors, openApiFiles, pagesAcc, {
            overwrite: true,
            writeFiles: true,
            targetDir,
            localSchema,
        }),
        generateOpenApiAnchorOrTab(mintConfig.tabs, openApiFiles, pagesAcc, {
            overwrite: true,
            writeFiles: true,
            targetDir,
            localSchema,
        }),
    ]);
    const newNav = [
        ...mintConfig.navigation,
        ...anchorOpenApiInfo.newNavItems,
        ...tabOpenApiInfo.newNavItems,
    ];
    return {
        mintConfig: { ...mintConfig, navigation: newNav },
        pagesAcc,
        openApiFiles: [
            ...openApiFiles,
            ...anchorOpenApiInfo.newOpenApiFiles,
            ...tabOpenApiInfo.newOpenApiFiles,
        ],
    };
};
export const generateOpenApiAnchorOrTab = async (anchorsOrTabs, openApiFiles, pagesAcc, opts) => {
    const { overwrite, writeFiles, targetDir, localSchema } = opts;
    const newNavItems = [];
    const newOpenApiFiles = [];
    if (anchorsOrTabs == undefined)
        return { newNavItems, newOpenApiFiles };
    const promises = [];
    for (const [i, anchorOrTab] of anchorsOrTabs.entries()) {
        if (anchorOrTab.openapi == undefined)
            continue;
        let openApiFile = undefined;
        if (isAllowedLocalSchemaUrl(anchorOrTab.openapi, localSchema)) {
            try {
                const document = await getOpenApiDocumentFromUrl(anchorOrTab.openapi);
                openApiFile = {
                    filename: `openapi-from-anchor-url-${i}`,
                    spec: document,
                };
                newOpenApiFiles.push(openApiFile);
            }
            catch (err) {
                console.error(err);
                throw err;
            }
        }
        else {
            openApiFile = openApiFiles.find((file) => file.originalFileLocation != undefined &&
                file.originalFileLocation === anchorOrTab.openapi);
        }
        if (openApiFile == undefined) {
            throw new Error(`Openapi file "${anchorOrTab.openapi}" defined in the anchor or tab array at index ${i} in your mint.json does not exist`);
        }
        promises.push((async () => {
            const { pagesAcc: pagesAccFromGeneratedOpenApiPages, nav: navFromGeneratedOpenApiPages } = await generateOpenApiPages(openApiFile.spec, {
                openApiFilePath: openApiFile.originalFileLocation,
                version: anchorOrTab.version,
                writeFiles,
                outDir: anchorOrTab.url,
                outDirBasePath: path.join(targetDir ?? '', 'src', '_props'),
                overwrite,
                localSchema,
            });
            Object.entries(pagesAccFromGeneratedOpenApiPages).forEach(([key, value]) => {
                pagesAcc[key] = value;
            });
            newNavItems.push(...navFromGeneratedOpenApiPages);
        })());
    }
    await Promise.all(promises);
    return { newNavItems, newOpenApiFiles };
};
