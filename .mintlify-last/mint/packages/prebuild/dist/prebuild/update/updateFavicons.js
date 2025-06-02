import { outputFile } from 'fs-extra';
import path from 'path';
import { generateFavicons } from '../generateFavicons.js';
export const updateFavicons = async (config, contentDirectoryPath) => {
    const generatedFavicons = await generateFavicons(config, contentDirectoryPath);
    if (!generatedFavicons)
        return;
    const promises = [];
    generatedFavicons.forEach((icons) => {
        icons.images.forEach((img) => {
            promises.push((async () => {
                const targetPath = path.join('public', 'favicons', img.name);
                await outputFile(targetPath, Buffer.from(img.contents), {
                    flag: 'w',
                });
            })());
        });
    });
    generatedFavicons.forEach((icon) => {
        icon.files.forEach((file) => {
            promises.push((async () => {
                const targetPath = path.join('public', 'favicons', file.name);
                await outputFile(targetPath, file.contents, { flag: 'w' });
            })());
        });
    });
    await Promise.all(promises);
};
