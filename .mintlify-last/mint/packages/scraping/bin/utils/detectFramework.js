import { visit, EXIT, CONTINUE } from 'unist-util-visit';
import { log } from './log.js';
export const framework = {
    vendor: undefined,
    version: undefined,
};
export function detectFramework(rootHast) {
    visit(rootHast, 'element', function (node) {
        if (node.tagName === 'link' &&
            Array.isArray(node.properties.rel) &&
            node.properties.rel.includes('preconnect') &&
            node.properties.href === 'https://api.gitbook.com') {
            framework.vendor = 'gitbook';
            framework.version = undefined;
            return EXIT;
        }
        // All of the other docs vendors rely on
        // the `meta` element as well as a `name`
        // property which should be a string
        if (node.tagName !== 'meta' || typeof node.properties.name !== 'string')
            return CONTINUE;
        switch (node.properties.name) {
            case 'readme-deploy':
                framework.vendor = 'readme';
                framework.version = undefined;
                return EXIT;
            // case "intercom: trackingEvent":
            //   framework.vendor = "intercom";
            //   framework.version = undefined;
            //   return EXIT;
            case 'generator':
                if (typeof node.properties.content === 'string' &&
                    node.properties.content.includes('Docusaurus')) {
                    framework.vendor = 'docusaurus';
                    const meta = node.properties.content;
                    if (meta.includes('v3')) {
                        framework.version = 3;
                    }
                    else if (meta.includes('v2')) {
                        framework.version = 2;
                    }
                    else if (meta.includes('v1')) {
                        log('We detected Docusaurus version 1 but we only support scraping versions 2 and 3', 'error');
                        framework.vendor = undefined;
                        framework.version = undefined;
                    }
                    return EXIT;
                }
        }
    });
    if (framework.vendor) {
        log('Successfully detected documentation vendor: ' + framework.vendor);
    }
    else {
        log('Failed to detect documentation vendor; please contact support@mintlify.com');
        framework.version = undefined;
        process.exit(1);
    }
}
//# sourceMappingURL=detectFramework.js.map