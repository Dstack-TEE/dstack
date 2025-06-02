import { getOpenApiDocumentFromUrl, optionallyAddLeadingSlash, isAllowedLocalSchemaUrl, } from '@mintlify/common';
import { generateOpenApiPagesForDocsConfig } from '@mintlify/scraping';
import { divisions } from '@mintlify/validation';
import * as path from 'path';
const DEFAULT_OUTPUT_DIR = 'api-reference';
export const generateOpenApiFromDocsConfig = async (navigation, openApiFiles, pagesAcc, opts) => {
    const { overwrite, writeFiles, targetDir, localSchema } = opts;
    const newOpenApiFiles = [];
    async function processOpenApiInNav(nav) {
        let outputDir = DEFAULT_OUTPUT_DIR;
        let openapi;
        if ('openapi' in nav) {
            if (typeof nav.openapi === 'string') {
                openapi = nav.openapi;
            }
            else if (Array.isArray(nav.openapi) && nav.openapi.length > 0) {
                // TODO: handle multiple openapi files
                openapi = nav.openapi[0];
            }
            else if (typeof nav.openapi === 'object' && 'source' in nav.openapi) {
                openapi = nav.openapi.source;
                outputDir = nav.openapi.directory ?? DEFAULT_OUTPUT_DIR;
            }
        }
        if (openapi) {
            let openApiFile = undefined;
            if (isAllowedLocalSchemaUrl(openapi, localSchema)) {
                openApiFile = await createOpenApiFile(openapi);
                newOpenApiFiles.push(openApiFile);
            }
            else {
                openApiFile = openApiFiles.find((file) => file.originalFileLocation != undefined &&
                    file.originalFileLocation === optionallyAddLeadingSlash(openapi));
            }
            if (!openApiFile) {
                throw new Error(`Openapi file ${openapi} defined in ${getDivisionNav(nav)
                    ?.division} in your docs.json does not exist`);
            }
            const { pagesAcc: pagesAccFromGeneratedOpenApiPages, nav: navFromGeneratedOpenApiPages } = await generateOpenApiPagesForDocsConfig(openApiFile.spec, {
                openApiFilePath: openApiFile.originalFileLocation,
                writeFiles,
                outDir: outputDir,
                outDirBasePath: path.join(targetDir ?? '', 'src', '_props'),
                overwrite,
                localSchema,
            });
            Object.entries(pagesAccFromGeneratedOpenApiPages).forEach(([key, value]) => {
                pagesAcc[key] = value;
            });
            const divisionNav = getDivisionNav(nav);
            if (divisionNav?.division) {
                return {
                    [divisionNav.division]: divisionNav.name,
                    ...divisionNav.nav,
                    ...(divisionNav.division === 'group'
                        ? {
                            pages: 'pages' in nav
                                ? [...nav.pages, ...navFromGeneratedOpenApiPages]
                                : navFromGeneratedOpenApiPages,
                        }
                        : {
                            groups: 'groups' in nav
                                ? [...nav.groups, ...navFromGeneratedOpenApiPages]
                                : navFromGeneratedOpenApiPages,
                        }),
                };
            }
        }
        return null;
    }
    async function processNav(nav) {
        const processedNav = await processOpenApiInNav(nav);
        if (processedNav) {
            return processedNav;
        }
        let newNav = { ...nav };
        if ('pages' in newNav) {
            newNav.pages = await Promise.all(newNav.pages.map(async (page) => {
                if (typeof page === 'object' && page !== null && 'group' in page) {
                    return processNav(page);
                }
                return page;
            }));
        }
        for (const division of ['groups', ...divisions]) {
            if (division in newNav) {
                const items = newNav[division];
                newNav = {
                    ...newNav,
                    [division]: await Promise.all(items.map((item) => processNav(item))),
                };
            }
        }
        return newNav;
    }
    const processedNavigation = await processNav(navigation);
    navigation = processedNavigation;
    return {
        newNav: processedNavigation,
        newOpenApiFiles,
    };
};
function getDivisionNav(nav) {
    if ('openapi' in nav) {
        const { openapi: _, ...updatedNav } = nav;
        const divisionMap = {
            group: 'group',
            anchor: 'anchor',
            tab: 'tab',
            version: 'version',
            language: 'language',
            dropdown: 'dropdown',
        };
        const divisionType = Object.keys(divisionMap).find((key) => key in updatedNav);
        return {
            division: divisionMap[divisionType],
            name: updatedNav[divisionType],
            nav: updatedNav,
        };
    }
    return undefined;
}
async function createOpenApiFile(openApiUrl) {
    try {
        const document = await getOpenApiDocumentFromUrl(openApiUrl);
        return {
            filename: openApiUrl,
            spec: document,
            originalFileLocation: openApiUrl,
        };
    }
    catch (err) {
        console.error(err);
        throw err;
    }
}
