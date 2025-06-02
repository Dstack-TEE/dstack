import { getAsyncApiDocumentFromUrl, optionallyAddLeadingSlash, isAllowedLocalSchemaUrl, } from '@mintlify/common';
import { generateAsyncApiPagesForDocsConfig } from '@mintlify/scraping';
import { divisions } from '@mintlify/validation';
import * as path from 'path';
const DEFAULT_OUTPUT_DIR = 'api-reference';
export const generateAsyncApiFromDocsConfig = async (navigation, asyncApiFiles, pagesAcc, opts) => {
    const { overwrite, writeFiles, targetDir, localSchema } = opts;
    const newAsyncApiFiles = [];
    async function processAsyncApiInNav(nav) {
        let outputDir = DEFAULT_OUTPUT_DIR;
        let asyncApis = [];
        if ('asyncapi' in nav) {
            if (typeof nav.asyncapi === 'string') {
                asyncApis = [nav.asyncapi];
            }
            else if (Array.isArray(nav.asyncapi)) {
                asyncApis = nav.asyncapi;
            }
            else if (typeof nav.asyncapi === 'object' && 'source' in nav.asyncapi) {
                asyncApis = [nav.asyncapi.source];
                outputDir = nav.asyncapi.directory ?? DEFAULT_OUTPUT_DIR;
            }
        }
        if (asyncApis.length > 0) {
            const processedAsyncApiFiles = [];
            for (const asyncApi of asyncApis) {
                let asyncApiFile = undefined;
                if (isAllowedLocalSchemaUrl(asyncApi, localSchema)) {
                    asyncApiFile = await createAsyncApiFile(asyncApi);
                    newAsyncApiFiles.push(asyncApiFile);
                }
                else {
                    asyncApiFile = asyncApiFiles.find((file) => file.originalFileLocation === optionallyAddLeadingSlash(asyncApi));
                }
                if (!asyncApiFile) {
                    if (asyncApi === asyncApis[0] &&
                        asyncApiFiles.length > 0 &&
                        !asyncApiFiles[0]?.spec.channels().length) {
                        throw new Error('No channels defined');
                    }
                    throw new Error(`AsyncAPI file ${asyncApi} defined in ${getDivisionNav(nav)
                        ?.division} in your docs.json does not exist`);
                }
                processedAsyncApiFiles.push(asyncApiFile);
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            let allGeneratedNav = [];
            for (const asyncApiFile of processedAsyncApiFiles) {
                const { pagesAcc: pagesAccFromGeneratedAsyncApiPages, nav: navFromGeneratedAsyncApiPages } = await generateAsyncApiPagesForDocsConfig(asyncApiFile.spec, {
                    asyncApiFilePath: asyncApiFile.originalFileLocation,
                    writeFiles,
                    outDir: outputDir,
                    outDirBasePath: path.join(targetDir ?? '', 'src', '_props'),
                    overwrite,
                    localSchema,
                });
                Object.entries(pagesAccFromGeneratedAsyncApiPages).forEach(([key, value]) => {
                    pagesAcc[key] = value;
                });
                allGeneratedNav = [...allGeneratedNav, ...navFromGeneratedAsyncApiPages];
            }
            const divisionNav = getDivisionNav(nav);
            if (divisionNav?.division) {
                return {
                    [divisionNav.division]: divisionNav.name,
                    ...divisionNav.nav,
                    ...(divisionNav.division === 'group'
                        ? {
                            pages: 'pages' in nav ? [...nav.pages, ...allGeneratedNav] : allGeneratedNav,
                        }
                        : {
                            groups: 'groups' in nav ? [...nav.groups, ...allGeneratedNav] : allGeneratedNav,
                        }),
                };
            }
        }
        return null;
    }
    async function processNav(nav) {
        const processedNav = await processAsyncApiInNav(nav);
        if (processedNav) {
            return processedNav;
        }
        let newNav = { ...nav };
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
        newAsyncApiFiles,
    };
};
function getDivisionNav(nav) {
    if ('asyncapi' in nav) {
        const { asyncapi: _, ...updatedNav } = nav;
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
async function createAsyncApiFile(url) {
    try {
        const document = await getAsyncApiDocumentFromUrl(url);
        return {
            filename: url,
            spec: document,
            originalFileLocation: url,
        };
    }
    catch (err) {
        console.error(err);
        throw err;
    }
}
