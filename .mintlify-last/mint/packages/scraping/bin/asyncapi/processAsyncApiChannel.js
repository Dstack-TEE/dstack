import { optionallyAddLeadingSlash, camelToSentenceCase } from '@mintlify/common';
import fse from 'fs-extra';
import { outputFile } from 'fs-extra';
import { join, resolve } from 'path';
import { DEFAULT_WEBSOCKETS_GROUP_NAME, prepareStringToBeValidFilename, generateUniqueFilenameWithoutExtension, } from '../apiPages/common.js';
export const processAsyncApiChannel = ({ channel, nav, decoratedNav, writePromises, pagesAcc, opts, findNavGroup, }) => {
    const asyncApiFilePathFromRoot = opts?.asyncApiFilePath
        ? optionallyAddLeadingSlash(opts.asyncApiFilePath)
        : undefined;
    const tags = channel.tags().all();
    const groupName = tags[0]?.name() ?? DEFAULT_WEBSOCKETS_GROUP_NAME;
    const channelId = channel.id();
    const title = channel.title() ?? channelId;
    const filename = prepareStringToBeValidFilename(title) ?? '';
    const description = channel.description() ?? channel.summary() ?? '';
    const folder = prepareStringToBeValidFilename(groupName) ?? '';
    const base = join(opts?.outDir ?? '', folder, filename);
    const navGroup = findNavGroup(nav, groupName);
    const decoratedNavGroup = findNavGroup(decoratedNav, groupName);
    const filenameWithoutExtension = generateUniqueFilenameWithoutExtension(navGroup, base);
    const asyncApiMetaTag = `${asyncApiFilePathFromRoot ? `${asyncApiFilePathFromRoot} ` : ''}${channelId}`;
    navGroup.push(filenameWithoutExtension);
    const page = {
        asyncapi: asyncApiMetaTag,
        href: resolve('/', filenameWithoutExtension),
        title: title === channelId ? camelToSentenceCase(title) : title,
        description,
        version: opts?.version,
    };
    decoratedNavGroup.push(page);
    pagesAcc[filenameWithoutExtension] = page;
    const targetPath = opts?.outDirBasePath
        ? join(opts.outDirBasePath, `${filenameWithoutExtension}.mdx`)
        : `${filenameWithoutExtension}.mdx`;
    if (opts?.writeFiles && (!fse.pathExistsSync(targetPath) || opts.overwrite)) {
        writePromises.push(createAsyncApiFrontmatter(targetPath, asyncApiMetaTag, opts.version));
    }
};
const createAsyncApiFrontmatter = async (filename, asyncApiMetaTag, version) => {
    const data = `---
asyncapi: ${asyncApiMetaTag}${version ? `\nversion: ${version}` : ''}
---`;
    await outputFile(filename, data);
};
//# sourceMappingURL=processAsyncApiChannel.js.map