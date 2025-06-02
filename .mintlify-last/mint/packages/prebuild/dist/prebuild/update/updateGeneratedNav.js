import { outputFile } from 'fs-extra';
import path from 'path';
import { generateDecoratedDocsNavigationFromPages, generateDecoratedMintNavigationFromPages, } from '../../generate.js';
export const updateGeneratedNav = async (pages, configNav) => {
    const generatedNav = generateDecoratedMintNavigationFromPages(pages, configNav);
    const targetPath = path.join('src', '_props', 'generatedNav.json');
    await outputFile(targetPath, JSON.stringify(generatedNav, null, 2), {
        flag: 'w',
    });
};
export const updateGeneratedDocsNav = async (pages, docsConfigNav) => {
    const generatedNav = generateDecoratedDocsNavigationFromPages(pages, docsConfigNav);
    const targetPath = path.join('src', '_props', 'generatedDocsNav.json');
    await outputFile(targetPath, JSON.stringify(generatedNav, null, 2), {
        flag: 'w',
    });
};
