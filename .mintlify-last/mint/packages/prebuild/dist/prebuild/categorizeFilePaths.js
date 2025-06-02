import { openApiCheck } from '@mintlify/common';
import { validateAsyncApi } from '@mintlify/common';
import { readFile } from 'fs/promises';
import yaml from 'js-yaml';
import * as path from 'path';
import { getFileList } from '../fs/index.js';
import { getFileExtension } from '../utils.js';
export const categorizeFilePaths = async (contentDirectoryPath) => {
    const allFilesInCmdExecutionPath = getFileList(contentDirectoryPath);
    const contentFilenames = [];
    const staticFilenames = [];
    const openApiFiles = [];
    const asyncApiFiles = [];
    const snippets = [];
    const snippetsV2 = [];
    for await (const filename of allFilesInCmdExecutionPath) {
        const extension = getFileExtension(filename);
        switch (extension) {
            case 'mdx':
            case 'md':
                if (filename.startsWith('/_snippets/')) {
                    snippets.push(filename);
                    break;
                }
                if (filename.startsWith('/snippets/')) {
                    snippetsV2.push(filename);
                    break;
                }
                contentFilenames.push(filename);
                break;
            case 'json':
            case 'yaml':
            case 'yml':
                const filePath = path.join(contentDirectoryPath, filename);
                const str = await readFile(filePath, 'utf8');
                const obj = yaml.load(str);
                const isOpenApi = Object.keys(obj).includes('openapi');
                const isAsyncApi = Object.keys(obj).includes('asyncapi');
                const fileName = path.parse(filename).name;
                if (isOpenApi) {
                    try {
                        const openApiDocument = await openApiCheck(obj);
                        if (openApiDocument) {
                            openApiFiles.push({
                                filename: fileName,
                                spec: obj,
                                originalFileLocation: filename,
                            });
                        }
                    }
                    catch { }
                }
                if (isAsyncApi) {
                    try {
                        const { document: asyncApiDocument } = await validateAsyncApi(str);
                        if (asyncApiDocument) {
                            asyncApiFiles.push({
                                filename: fileName,
                                spec: asyncApiDocument,
                                originalFileLocation: filename,
                            });
                        }
                    }
                    catch { }
                }
                break;
            default:
                staticFilenames.push(filename);
        }
    }
    return { contentFilenames, staticFilenames, openApiFiles, asyncApiFiles, snippets, snippetsV2 };
};
