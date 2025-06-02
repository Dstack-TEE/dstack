import { stringifyTree } from '@mintlify/common';
import { upgradeToDocsConfig } from '@mintlify/validation';
import { outputFile } from 'fs-extra';
import { updateDocsConfigFile } from './docsConfig/index.js';
import { updateMintConfigFile } from './mintConfig/index.js';
import { readPageContents, readSnippetsV2Contents } from './read/readContent.js';
import { resolveImportsAndWriteFiles } from './resolveImportsAndWriteFiles.js';
import { updateFavicons } from './updateFavicons.js';
import { updateGeneratedDocsNav, updateGeneratedNav } from './updateGeneratedNav.js';
import { writeAsyncApiFiles } from './write/writeAsyncApiFiles.js';
import { writeFiles } from './write/writeFiles.js';
import { writeOpenApiFiles } from './write/writeOpenApiFiles.js';
export const update = async ({ contentDirectoryPath, staticFilenames, openApiFiles, asyncApiFiles, contentFilenames, snippets, snippetV2Filenames, docsConfigPath, localSchema, }) => {
    const mintConfigResult = await updateMintConfigFile(contentDirectoryPath, openApiFiles, localSchema);
    // we used the original mint config without openapi pages injected
    // because we will do it in `updateDocsConfigFile`, this will avoid duplicated openapi pages
    const docsConfig = mintConfigResult != null ? upgradeToDocsConfig(mintConfigResult.originalMintConfig) : undefined;
    const { docsConfig: newDocsConfig, pagesAcc, newOpenApiFiles, newAsyncApiFiles, } = await updateDocsConfigFile(contentDirectoryPath, openApiFiles, asyncApiFiles, docsConfigPath ? undefined : docsConfig, localSchema);
    const pagePromises = readPageContents({
        contentDirectoryPath,
        openApiFiles: newOpenApiFiles,
        asyncApiFiles: newAsyncApiFiles,
        contentFilenames,
        pagesAcc,
    });
    const snippetV2Promises = readSnippetsV2Contents(contentDirectoryPath, snippetV2Filenames);
    const [snippetV2Contents, { mdxFilesWithNoImports, filesWithImports }] = await Promise.all([
        snippetV2Promises,
        pagePromises,
    ]);
    await Promise.all([
        resolveImportsAndWriteFiles({
            openApiFiles: newOpenApiFiles,
            asyncApiFiles: newAsyncApiFiles,
            pagesAcc,
            snippetsV2: snippetV2Contents,
            filesWithImports,
        }),
        writeOpenApiFiles(newOpenApiFiles),
        writeAsyncApiFiles(newAsyncApiFiles),
        updateFavicons(newDocsConfig, contentDirectoryPath),
        ...writeMdxFilesWithNoImports(mdxFilesWithNoImports),
        ...writeFiles(contentDirectoryPath, 'public', [...staticFilenames, ...snippets]),
    ]);
    await updateGeneratedDocsNav(pagesAcc, newDocsConfig.navigation);
    if (mintConfigResult?.mintConfig) {
        await updateGeneratedNav(pagesAcc, mintConfigResult.mintConfig.navigation);
    }
    return newDocsConfig;
};
export const writeMdxFilesWithNoImports = (mdxFilesWithNoImports) => {
    return mdxFilesWithNoImports.map(async (response) => {
        const { targetPath, tree } = response;
        await outputFile(targetPath, stringifyTree(tree), {
            flag: 'w',
        });
    });
};
export * from './mintConfig/index.js';
export * from './docsConfig/index.js';
export * from './ConfigUpdater.js';
