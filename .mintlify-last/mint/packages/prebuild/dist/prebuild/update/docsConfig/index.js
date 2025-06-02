import { getConfigPath } from '../../../utils.js';
import { DocsConfigUpdater } from '../ConfigUpdater.js';
import { generateAsyncApiDivisions } from './generateAsyncApiDivisions.js';
import { generateOpenApiDivisions } from './generateOpenApiDivisions.js';
export async function updateDocsConfigFile(contentDirectoryPath, openApiFiles, asyncApiFiles, docsConfig, localSchema) {
    const configPath = await getConfigPath(contentDirectoryPath, 'docs');
    if (configPath == null && docsConfig == null) {
        throw Error('Must be run in a directory where a docs.json file exists.');
    }
    if (docsConfig == null && configPath) {
        docsConfig = await DocsConfigUpdater.getConfig(configPath);
    }
    if (docsConfig == null) {
        throw Error('Must be run in a directory where a docs.json file exists.');
    }
    const { newDocsConfig: docsConfigWithOpenApiPages, pagesAcc: pagesAccWithOpenApiPages, openApiFiles: newOpenApiFiles, } = await generateOpenApiDivisions(docsConfig, openApiFiles, undefined, localSchema);
    const { newDocsConfig, pagesAcc: pagesAccWithAsyncApiPages, asyncApiFiles: newAsyncApiFiles, } = await generateAsyncApiDivisions(docsConfigWithOpenApiPages, asyncApiFiles, undefined, localSchema);
    const pagesAcc = { ...pagesAccWithOpenApiPages, ...pagesAccWithAsyncApiPages };
    await DocsConfigUpdater.writeConfigFile(newDocsConfig);
    return { docsConfig: newDocsConfig, pagesAcc, newOpenApiFiles, newAsyncApiFiles };
}
export { generateOpenApiDivisions } from './generateOpenApiDivisions.js';
export { generateOpenApiFromDocsConfig } from './generateOpenApiFromDocsConfig.js';
export { generateAsyncApiDivisions } from './generateAsyncApiDivisions.js';
export { generateAsyncApiFromDocsConfig } from './generateAsyncApiFromDocsConfig.js';
