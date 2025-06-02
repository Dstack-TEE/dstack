import { slugToTitle, optionallyAddLeadingSlash } from '@mintlify/common';
import { divisions, } from '@mintlify/validation';
const handleUnknownPage = (page, type) => {
    console.log(`⚠️   "${page}" is defined in the ${type}.json navigation but the file does not exist.`);
    return {
        title: slugToTitle(page),
        href: optionallyAddLeadingSlash(page),
    };
};
export const generateDecoratedMintNavigationFromPages = (filenamePageMetadataMap, mintConfigNav) => {
    const createNav = (nav) => {
        return {
            ...nav,
            pages: nav.pages.map((page) => {
                if (typeof page === 'string') {
                    const pageMetadata = filenamePageMetadataMap[page];
                    if (pageMetadata) {
                        return pageMetadata;
                    }
                    else {
                        return handleUnknownPage(page, 'mint');
                    }
                }
                return createNav(page);
            }),
        };
    };
    return mintConfigNav.map((nav) => createNav(nav));
};
export const generateDecoratedDocsNavigationFromPages = (filenamePageMetadataMap, docsConfigNav) => {
    const { global, ...nav } = docsConfigNav;
    const generateDecoratedPages = (page) => {
        const pageMetadata = filenamePageMetadataMap[page];
        if (pageMetadata) {
            return pageMetadata;
        }
        else {
            return handleUnknownPage(page, 'docs');
        }
    };
    const traverseNav = (nav) => {
        let processed = { ...nav };
        if ('openapi' in processed) {
            const { openapi: _, ...rest } = processed;
            processed = { ...rest };
        }
        if ('pages' in processed) {
            if ('root' in processed && typeof processed.root === 'string') {
                processed.root = generateDecoratedPages(processed.root);
            }
            processed.pages = processed.pages.map((page) => typeof page === 'string' ? generateDecoratedPages(page) : traverseNav(page));
        }
        ['groups', ...divisions].forEach((division) => {
            const divisionNav = processed[division];
            if (Array.isArray(divisionNav)) {
                processed = { ...processed, [division]: divisionNav.map((item) => traverseNav(item)) };
            }
        });
        return processed;
    };
    return { global, ...traverseNav(nav) };
};
