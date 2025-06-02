import { getConfigPath } from '../../../utils.js';
import { MintConfigUpdater } from '../ConfigUpdater.js';
import { generateOpenApiAnchorsOrTabs } from './generateOpenApiAnchorsOrTabs.js';
export async function updateMintConfigFile(contentDirectoryPath, openApiFiles, localSchema) {
    const configPath = await getConfigPath(contentDirectoryPath, 'mint');
    if (configPath == null) {
        return null;
    }
    const mintConfig = await MintConfigUpdater.getConfig(configPath);
    const { mintConfig: newMintConfig, pagesAcc, openApiFiles: newOpenApiFiles, } = await generateOpenApiAnchorsOrTabs(mintConfig, openApiFiles, undefined, localSchema);
    await MintConfigUpdater.writeConfigFile(newMintConfig);
    return {
        mintConfig: newMintConfig,
        pagesAcc,
        openApiFiles: newOpenApiFiles,
        originalMintConfig: mintConfig,
    };
}
export { generateOpenApiAnchorsOrTabs, generateOpenApiAnchorOrTab, } from './generateOpenApiAnchorsOrTabs.js';
