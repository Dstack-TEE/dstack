import fse from 'fs-extra';
import { load } from 'js-yaml';
export const writeAsyncApiFiles = async (asyncApiFiles) => {
    const asyncApiTargetPath = 'src/_props/asyncApiFiles.json';
    const asyncApiFilesToSave = asyncApiFiles.map(({ filename, spec, originalFileLocation }) => {
        const originalSpec = spec['_meta']['asyncapi']['input'];
        const asyncApiDocument = load(originalSpec);
        return {
            filename,
            spec: asyncApiDocument,
            originalFileLocation,
        };
    });
    await fse.remove(asyncApiTargetPath);
    await fse.outputFile(asyncApiTargetPath, JSON.stringify(asyncApiFilesToSave), {
        flag: 'w',
    });
};
