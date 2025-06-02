import { validateAsyncApi } from '@mintlify/common';
import yaml from 'js-yaml';
import { launch } from 'puppeteer';
import { framework } from './detectFramework.js';
import { getErrorMessage } from './errors.js';
import { log } from './log.js';
const userAgents = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
];
const headers = {
    'Accept-Language': 'en-US,en;q=0.9',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    Connection: 'keep-alive',
};
async function exponentialBackoff(operation, retries = 3, delay = 1000, factor = 2) {
    try {
        return await operation();
    }
    catch (error) {
        if (retries > 0) {
            await new Promise((resolve) => setTimeout(resolve, delay));
            return exponentialBackoff(operation, retries - 1, delay * factor, factor);
        }
        else {
            throw error;
        }
    }
}
export async function startPuppeteer() {
    try {
        return await launch({
            headless: true,
            ignoreHTTPSErrors: true,
        });
    }
    catch (error) {
        if (error instanceof Error) {
            log(`Could not create a browser instance: ${error.message}`);
        }
    }
}
export async function getHtmlWithPuppeteer(browser, url) {
    try {
        const page = await browser.newPage();
        await page.setViewport({
            width: 3072,
            height: 2048,
            deviceScaleFactor: 2,
            isMobile: false,
            hasTouch: false,
            isLandscape: true,
        });
        await page.setExtraHTTPHeaders(headers);
        await page.setUserAgent(userAgents[Math.floor(Math.random() * userAgents.length)] || userAgents[0]);
        await page.setJavaScriptEnabled(true);
        await exponentialBackoff(() => page.goto(url.toString(), {
            waitUntil: 'networkidle2',
            timeout: 30000,
        }));
        if (framework.vendor === 'docusaurus') {
            await page.evaluate(() => {
                document.addEventListener('click', (e) => {
                    if (e.target instanceof Element && e.target.classList.contains('menu__link--sublist'))
                        e.preventDefault();
                }, true);
                function clickItems(el) {
                    const menuItems = el.getElementsByClassName('menu__link--sublist');
                    for (const item of menuItems) {
                        item.click();
                        clickItems(item);
                    }
                }
                clickItems(document);
            });
        }
        const content = await exponentialBackoff(() => page.content());
        await page.close();
        return content;
    }
    catch (error) {
        const errorMessage = getErrorMessage(error);
        throw new Error(`Failed to download page from Puppeteer${errorMessage}`);
    }
}
async function fetchPageResponse(url) {
    try {
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error(`${res.status} ${res.statusText}`);
        }
        return await res.text();
    }
    catch (error) {
        const errorMessage = getErrorMessage(error);
        throw new Error(`Failed to fetch page from source${errorMessage}`);
    }
}
export async function fetchPageHtml(url, browser = undefined) {
    try {
        let res = undefined;
        if (browser) {
            res = await getHtmlWithPuppeteer(browser, url);
        }
        else {
            res = await exponentialBackoff(() => fetchPageResponse(url));
        }
        if (res)
            return res;
        throw new Error('An unknown error occured.');
    }
    catch (error) {
        const errorMessage = getErrorMessage(error);
        throw new Error(`Error retrieving HTML for ${url.toString()}${errorMessage}`);
    }
}
export async function fetchImage(url) {
    try {
        const res = await exponentialBackoff(() => fetch(url));
        if (!res.ok) {
            throw new Error(`${res.status} ${res.statusText}`);
        }
        const imageBuffer = await res.arrayBuffer();
        const imageData = new Uint8Array(imageBuffer);
        return imageData;
    }
    catch (error) {
        const errorMessage = getErrorMessage(error);
        throw new Error(`${url} - failed to retrieve image from source${errorMessage}`);
    }
}
export async function fetchOpenApi(url) {
    try {
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error(`${res.status} ${res.statusText}`);
        }
        const file = await res.text();
        return yaml.load(file);
    }
    catch (error) {
        const errorMessage = getErrorMessage(error);
        throw new Error(`${url} - failed to retrieve OpenAPI file from source${errorMessage}`);
    }
}
export async function fetchAsyncApi(url) {
    try {
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error(`${res.status} ${res.statusText}`);
        }
        const file = await res.text();
        const { document, errorMessage } = await validateAsyncApi(file);
        if (!document) {
            throw new Error(`${url} - this document is not a valid AsyncAPI document - ${errorMessage}`);
        }
        return document;
    }
    catch (error) {
        const errorMessage = getErrorMessage(error);
        throw new Error(`${url} - failed to retrieve AsyncAPI file from source - ${errorMessage}`);
    }
}
//# sourceMappingURL=network.js.map