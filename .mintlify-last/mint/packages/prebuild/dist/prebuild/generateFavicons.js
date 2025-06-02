import favicons from 'favicons';
import { readFile } from 'fs/promises';
import { join } from 'path';
export async function generateFavicons(config, contentDirectoryPath) {
    if (config.favicon == null)
        return;
    const faviconsConfig = getFaviconsConfig(config.name);
    try {
        if (typeof config.favicon === 'string') {
            const desiredPath = join(contentDirectoryPath, config.favicon);
            const favicon = await readFile(desiredPath);
            const icons = await favicons(favicon, faviconsConfig);
            return [icons];
        }
        else {
            const lightPath = join(contentDirectoryPath, config.favicon.light);
            const darkPath = join(contentDirectoryPath, config.favicon.dark);
            const lightFavicon = await readFile(lightPath);
            const darkFavicon = await readFile(darkPath);
            const [lightIcons, darkIcons] = await Promise.all([
                favicons(lightFavicon, faviconsConfig),
                favicons(darkFavicon, { ...faviconsConfig, path: '/favicons-dark' }),
            ]);
            return [lightIcons, darkIcons];
        }
    }
    catch (err) {
        if (err instanceof Error) {
            console.log(err.message);
        }
    }
}
export function getFaviconsConfig(name) {
    return {
        path: '/favicons',
        appName: name,
        appShortName: name,
        dir: 'auto',
        lang: 'en-US',
        background: 'transparent',
        theme_color: 'transparent',
        appleStatusBarStyle: 'black-translucent',
        display: 'standalone',
        orientation: 'any',
        scope: '/',
        start_url: '/?homescreen=1',
        preferRelatedApplications: false,
        version: '1.0',
        pixel_art: false,
        loadManifestWithCredentials: true,
        manifestMaskable: false,
        icons: {
            android: ['android-chrome-192x192.png', 'android-chrome-256x256.png'],
            appleIcon: ['apple-touch-icon.png'],
            appleStartup: false,
            favicons: true,
            windows: ['mstile-150x150.png'],
            yandex: false,
        },
    };
}
