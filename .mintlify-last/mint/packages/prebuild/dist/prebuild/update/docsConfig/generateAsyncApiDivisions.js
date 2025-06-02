import { getAsyncApiFilesFromConfig } from '../read/getAsyncApiFilesFromConfig.js';
import { generateAsyncApiFromDocsConfig } from './generateAsyncApiFromDocsConfig.js';
export const generateAsyncApiDivisions = async (docsConfig, asyncApiFiles, targetDir, localSchema) => {
    const asyncApiFilesFromDocsConfig = await getAsyncApiFilesFromConfig(docsConfig, localSchema);
    const pagesAcc = {};
    const { newNav, newAsyncApiFiles } = await generateAsyncApiFromDocsConfig(docsConfig.navigation, asyncApiFiles, pagesAcc, {
        overwrite: true,
        writeFiles: true,
        targetDir,
        localSchema,
    });
    return {
        newDocsConfig: { ...docsConfig, navigation: newNav },
        pagesAcc,
        asyncApiFiles: [...asyncApiFiles, ...asyncApiFilesFromDocsConfig, ...newAsyncApiFiles],
    };
};
