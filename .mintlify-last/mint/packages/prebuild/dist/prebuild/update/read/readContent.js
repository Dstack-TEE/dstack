import { hasImports, findAndRemoveImports, getDecoratedNavPageAndSlug } from '@mintlify/common';
import { promises as _promises } from 'fs';
import { join } from 'path';
import { preparseMdxTree } from '../../../createPage/preparseMdx/index.js';
const { readFile } = _promises;
export const readPageContents = async ({ contentDirectoryPath, openApiFiles, asyncApiFiles, contentFilenames, pagesAcc, }) => {
    const filesWithImports = [];
    const pagePromises = contentFilenames.map(async (filename) => {
        const sourcePath = join(contentDirectoryPath, filename);
        const targetPath = join('src', '_props', filename);
        try {
            const contentStr = (await readFile(sourcePath)).toString();
            // if is snippet add to static file array
            const tree = await preparseMdxTree(contentStr, contentDirectoryPath, sourcePath);
            const importsResponse = await findAndRemoveImports(tree);
            if (hasImports(importsResponse)) {
                filesWithImports.push({
                    ...importsResponse,
                    filename,
                });
                return;
            }
            const { slug, pageMetadata } = getDecoratedNavPageAndSlug(filename, contentStr, openApiFiles, asyncApiFiles);
            pagesAcc[slug] = pageMetadata;
            return { targetPath, tree };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred reading and parsing file.';
            console.error(`${sourcePath}: ${errorMessage}`);
            throw new Error('Failed to parse MDX files, please correct errors before continuing');
        }
    });
    const mdxFilesWithNoImports = (await Promise.all(pagePromises)).filter((item) => item !== undefined);
    return { mdxFilesWithNoImports, pagesAcc, filesWithImports };
};
export const readSnippetsV2Contents = (contentDirectoryPath, snippetV2Filenames) => {
    const snippetV2Promises = snippetV2Filenames.map(async (filename) => {
        const sourcePath = join(contentDirectoryPath, filename);
        const contentStr = await readFile(sourcePath, 'utf8');
        const tree = await preparseMdxTree(contentStr, contentDirectoryPath, sourcePath);
        return { filename, tree };
    });
    return Promise.all(snippetV2Promises);
};
