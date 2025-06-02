import { resolveAllImports, hasImports, findAndRemoveImports, getDecoratedNavPageAndSlug, topologicalSort, stringifyTree, } from '@mintlify/common';
import { outputFile } from 'fs-extra';
import { join } from 'path';
export const resolveImportsAndWriteFiles = async ({ openApiFiles, asyncApiFiles, pagesAcc, snippetsV2, filesWithImports, }) => {
    const snippetsWithResolvedImports = await resolveImportsInSnippets(snippetsV2);
    const writeSnippetsWithImportsPromises = await writeSnippets(snippetsWithResolvedImports);
    const pagesWithResolvedImports = await resolveImportsInPages({
        openApiFiles,
        asyncApiFiles,
        snippetsWithResolvedImports,
        filesWithImports,
        pagesAcc,
    });
    const writePagesPromise = writePages(pagesWithResolvedImports);
    await Promise.all([...writeSnippetsWithImportsPromises, ...writePagesPromise]);
};
const resolveImportsInSnippets = async (snippetsV2) => {
    const snippetsWithImportsPromises = snippetsV2.map(async (snippet) => ({
        ...(await findAndRemoveImports(snippet.tree)),
        filename: snippet.filename,
    }));
    const snippetsWithImports = await Promise.all(snippetsWithImportsPromises);
    const graph = {};
    snippetsWithImports.forEach((snippetWithImports) => {
        graph[snippetWithImports.filename] = Object.keys(snippetWithImports.importMap);
    });
    const order = topologicalSort(graph).reverse();
    const orderedSnippetsWithImports = order
        .map((filename) => {
        return snippetsWithImports.find((snippet) => snippet.filename === filename);
    })
        .filter(Boolean);
    for (const snippetWithImports of orderedSnippetsWithImports) {
        if (hasImports(snippetWithImports)) {
            snippetWithImports.tree = await resolveAllImports({
                snippets: orderedSnippetsWithImports,
                fileWithImports: snippetWithImports,
            });
        }
    }
    return snippetsWithImports;
};
const writeSnippets = async (snippetsWithImports) => snippetsWithImports.map(async (snippetWithImports) => {
    const targetPath = join('public', snippetWithImports.filename);
    await outputFile(targetPath, stringifyTree(snippetWithImports.tree), {
        flag: 'w',
    });
});
const resolveImportsInPages = async ({ openApiFiles, asyncApiFiles, snippetsWithResolvedImports, filesWithImports, pagesAcc, }) => {
    const filesWithResolvedImportsPromises = filesWithImports.map(async (fileWithImports) => {
        const tree = await resolveAllImports({
            snippets: snippetsWithResolvedImports,
            fileWithImports,
        });
        const contentStr = stringifyTree(tree);
        const { slug, pageMetadata } = getDecoratedNavPageAndSlug(fileWithImports.filename, contentStr, openApiFiles, asyncApiFiles);
        pagesAcc[slug] = pageMetadata;
        const targetPath = join('src', '_props', fileWithImports.filename);
        return {
            targetPath,
            tree,
        };
    });
    return await Promise.all(filesWithResolvedImportsPromises);
};
const writePages = (filesWithResolvedImports) => filesWithResolvedImports.map(async ({ targetPath, tree }) => {
    await outputFile(targetPath, stringifyTree(tree), {
        flag: 'w',
    });
});
