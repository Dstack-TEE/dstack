import { getOpenApiFilesFromConfig } from '../read/getOpenApiFilesFromConfig.js';
import { generateOpenApiFromDocsConfig } from './generateOpenApiFromDocsConfig.js';
export const generateOpenApiDivisions = async (docsConfig, openApiFiles, targetDir, localSchema) => {
    const openapiFilesFromDocsConfig = await getOpenApiFilesFromConfig('docs', docsConfig, localSchema);
    openApiFiles.push(...openapiFilesFromDocsConfig);
    const pagesAcc = {};
    const { newNav, newOpenApiFiles } = await generateOpenApiFromDocsConfig(docsConfig.navigation, openApiFiles, pagesAcc, {
        overwrite: true,
        writeFiles: true,
        targetDir,
        localSchema,
    });
    return {
        newDocsConfig: { ...docsConfig, navigation: newNav },
        pagesAcc,
        openApiFiles: [...openApiFiles, ...newOpenApiFiles],
    };
};
