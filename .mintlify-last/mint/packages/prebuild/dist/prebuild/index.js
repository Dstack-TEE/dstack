import { getConfigPath } from '../utils.js';
import { categorizeFilePaths } from './categorizeFilePaths.js';
import { update } from './update/index.js';
export const prebuild = async (contentDirectoryPath, { localSchema } = {}) => {
    if (process.env.IS_MULTI_TENANT === 'true') {
        console.log('Skipping prebuild in multi-tenant mode.');
        return;
    }
    const docsConfigPath = await getConfigPath(contentDirectoryPath, 'docs');
    const mintConfigPath = await getConfigPath(contentDirectoryPath, 'mint');
    if (mintConfigPath == null && docsConfigPath == null) {
        throw Error('Must be run in a directory where a mint.json or docs.json file exists.');
    }
    const { contentFilenames, staticFilenames, openApiFiles, asyncApiFiles, snippets, snippetsV2 } = await categorizeFilePaths(contentDirectoryPath);
    await update({
        contentDirectoryPath,
        staticFilenames,
        openApiFiles,
        asyncApiFiles,
        contentFilenames,
        snippets,
        snippetV2Filenames: snippetsV2,
        docsConfigPath,
        localSchema,
    });
};
export * from './categorizeFilePaths.js';
export * from '../createPage/index.js';
export * from '../createPage/preparseMdx/index.js';
export * from './update/index.js';
