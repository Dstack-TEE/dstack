import { validateMintConfig, validateDocsConfig, formatIssue, } from '@mintlify/validation';
import Chalk from 'chalk';
import { promises as _promises } from 'fs';
import { outputFile } from 'fs-extra';
import { join } from 'path';
const { readFile } = _promises;
export class ConfigUpdater {
    constructor(type) {
        this.validateConfigJsonString = async (configContents) => {
            const configObj = this.parseConfigJson(configContents);
            const validationResults = this.type === 'mint' ? validateMintConfig(configObj) : validateDocsConfig(configObj);
            if (!validationResults.success) {
                console.error(Chalk.red(`🚨 Invalid ${this.type}.json:`));
                validationResults.error.issues.forEach((issue) => console.error(Chalk.red(formatIssue(issue))));
                throw Error();
            }
            if (validationResults.warnings.length > 0) {
                if (validationResults.warnings.length > 0) {
                    console.warn(Chalk.yellow(`⚠️ Warnings found in ${this.type}.json:`));
                    validationResults.warnings.forEach((issue) => console.warn(Chalk.yellow(formatIssue(issue))));
                }
            }
            return { ...validationResults, data: validationResults.data };
        };
        this.readConfigFile = async (configPath) => {
            let configContents;
            try {
                configContents = await readFile(configPath, 'utf-8');
            }
            catch (err) {
                throw Error(`Unable to read ${this.type}.json: ${err}`);
            }
            return configContents;
        };
        this.writeConfigFile = async (config, targetDir) => {
            try {
                await outputFile(join(targetDir ?? '', `src/_props/${this.type}.json`), JSON.stringify(config, null, 2), {
                    flag: 'w',
                });
            }
            catch (err) {
                throw Error(`Unable to write ${this.type}.json: ${err}`);
            }
        };
        this.parseConfigJson = (configContents) => {
            let configObj;
            try {
                configObj = JSON.parse(configContents);
            }
            catch (e) {
                if (typeof e === 'object' && e != null) {
                    if ('name' in e && e.name === 'SyntaxError') {
                        console.error(`🚨 ${Chalk.red(`${this.type}.json has invalid JSON. You are likely missing a comma or a bracket. You can paste your ${this.type}.json file into https://jsonlint.com/ to get a more specific error message.`)}`);
                    }
                    else if ('message' in e) {
                        console.error(`🚨 ${Chalk.red(e.message)}`);
                    }
                }
                throw Error();
            }
            return configObj;
        };
        this.type = type;
    }
    getConfigType() {
        return this.type;
    }
    async getConfig(configPath) {
        const configContents = await this.readConfigFile(configPath);
        const validationResults = await this.validateConfigJsonString(configContents);
        return validationResults.data;
    }
}
export const MintConfigUpdater = new ConfigUpdater('mint');
export const DocsConfigUpdater = new ConfigUpdater('docs');
