import { coreRemark, getAST } from '@mintlify/common';
import { formatError } from '../../errorMessages/formatError.js';
export const preparseMdx = async (fileContent, contentDirectoryPath, filePath, suppressErrLog = false) => {
    try {
        return String(await coreRemark().process(fileContent));
    }
    catch (error) {
        if (!suppressErrLog) {
            console.error(formatError(error, filePath, contentDirectoryPath));
        }
        return `🚧 A parsing error occured. Please contact the owner of this website.`;
    }
};
export const preparseMdxTree = async (fileContent, contentDirectoryPath, filePath, suppressErrLog = false) => {
    try {
        return getAST(fileContent);
    }
    catch (error) {
        if (!suppressErrLog) {
            console.error(formatError(error, filePath, contentDirectoryPath));
        }
        return getAST(`🚧 A parsing error occured. Please contact the owner of this website.`);
    }
};
