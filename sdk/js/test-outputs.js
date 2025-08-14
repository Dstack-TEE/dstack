#!/usr/bin/env node

const { DstackClient, TappdClient, getComposeHash, verifyEnvEncryptPublicKey } = require('./dist/node/index.js');
const { toViemAccount, toViemAccountSecure } = require('./dist/node/viem.js');
const { toKeypair, toKeypairSecure } = require('./dist/node/solana.js');

async function main() {
    console.log("=== JS SDK Output Test ===");
    
    try {
        // Test client get_key
        const client = new DstackClient();
        console.log("\n1. Testing DstackClient.getKey()");
        
        const testPaths = [
            { path: "test/wallet", purpose: "ethereum" },
            { path: "test/signing", purpose: "solana" },
            { path: "user/alice", purpose: "mainnet" }
        ];
        
        for (const { path, purpose } of testPaths) {
            const keyResult = await client.getKey(path, purpose);
            console.log(`getKey('${path}', '${purpose}'):`);
            console.log(`  key: ${Buffer.from(keyResult.key).toString('hex')}`);
            console.log(`  signature_chain length: ${keyResult.signature_chain.length}`);
            console.log(`  signature_chain[0]: ${Buffer.from(keyResult.signature_chain[0]).toString('hex')}`);
        }

        // Test viem integration
        console.log("\n2. Testing Viem Integration");
        const ethKey = await client.getKey("eth/test", "wallet");
        
        console.log("\n2.1 toViemAccount (legacy):");
        try {
            const account = toViemAccount(ethKey);
            console.log(`  address: ${account.address}`);
            console.log(`  type: ${account.type}`);
        } catch (error) {
            console.log(`  error: ${error.message}`);
        }
        
        console.log("\n2.2 toViemAccountSecure:");
        try {
            const accountSecure = toViemAccountSecure(ethKey);
            console.log(`  address: ${accountSecure.address}`);
            console.log(`  type: ${accountSecure.type}`);
        } catch (error) {
            console.log(`  error: ${error.message}`);
        }

        // Test solana integration
        console.log("\n3. Testing Solana Integration");
        const solKey = await client.getKey("sol/test", "wallet");
        
        console.log("\n3.1 toKeypair (legacy):");
        try {
            const keypair = toKeypair(solKey);
            console.log(`  publicKey: ${keypair.publicKey.toString()}`);
            console.log(`  secretKey length: ${keypair.secretKey.length}`);
            console.log(`  secretKey (first 32 bytes): ${Buffer.from(keypair.secretKey.slice(0, 32)).toString('hex')}`);
        } catch (error) {
            console.log(`  error: ${error.message}`);
        }
        
        console.log("\n3.2 toKeypairSecure:");
        try {
            const keypairSecure = toKeypairSecure(solKey);
            console.log(`  publicKey: ${keypairSecure.publicKey.toString()}`);
            console.log(`  secretKey length: ${keypairSecure.secretKey.length}`);
            console.log(`  secretKey (first 32 bytes): ${Buffer.from(keypairSecure.secretKey.slice(0, 32)).toString('hex')}`);
        } catch (error) {
            console.log(`  error: ${error.message}`);
        }

        // Test TappdClient (deprecated)
        console.log("\n4. Testing TappdClient (deprecated)");
        try {
            const tappdClient = new TappdClient();
            console.log("\n4.1 TappdClient.getKey():");
            const tappdKey = await tappdClient.getKey("test/wallet", "ethereum");
            console.log(`  key: ${Buffer.from(tappdKey.key).toString('hex')}`);
            console.log(`  signature_chain length: ${tappdKey.signature_chain.length}`);

            console.log("\n4.2 TappdClient.tdxQuote():");
            const tappdQuote = await tappdClient.tdxQuote("test-data", "raw");
            console.log(`  quote length: ${tappdQuote.quote.length}`);
            console.log(`  event_log length: ${tappdQuote.event_log.length}`);
            console.log(`  rtmrs count: ${tappdQuote.replayRtmrs().length}`);
        } catch (error) {
            console.log(`  error: ${error.message}`);
        }

        // Test quotes
        console.log("\n5. Testing Quote Methods");
        console.log("\n5.1 DstackClient.getQuote():");
        const dstackQuote = await client.getQuote("test-data-for-quote");
        console.log(`  quote length: ${dstackQuote.quote.length}`);
        console.log(`  event_log length: ${dstackQuote.event_log.length}`);
        console.log(`  rtmrs count: ${dstackQuote.replayRtmrs().length}`);

        // Test getComposeHash
        console.log("\n6. Testing getComposeHash");
        const testComposes = [
            {
                manifest_version: 1,
                name: "test-app",
                runner: "docker-compose",
                docker_compose_file: "services:\\n  app:\\n    image: test\\n    ports:\\n      - 8080:8080"
            },
            {
                manifest_version: 1,
                name: "another-app", 
                runner: "docker-compose",
                docker_compose_file: "services:\\n  web:\\n    build: .\\n    environment:\\n      - NODE_ENV=production"
            }
        ];
        
        testComposes.forEach((compose, index) => {
            const hash = getComposeHash(compose);
            console.log(`compose ${index + 1}: ${hash}`);
            console.log(`  name: ${compose.name}`);
            console.log(`  runner: ${compose.runner}`);
        });

        // Test verifyEnvEncryptPublicKey
        console.log("\n7. Testing verifyEnvEncryptPublicKey");
        const testCases = [
            {
                publicKey: Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex'),
                signature: Buffer.from('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00', 'hex'),
                appId: '0000000000000000000000000000000000000000'
            },
            {
                publicKey: Buffer.from('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex'),
                signature: Buffer.from('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex'),
                appId: 'invalid-app-id'
            }
        ];

        testCases.forEach((testCase, index) => {
            try {
                const result = verifyEnvEncryptPublicKey(testCase.publicKey, testCase.signature, testCase.appId);
                console.log(`test case ${index + 1}: ${result ? Buffer.from(result).toString('hex') : 'null'}`);
            } catch (error) {
                console.log(`test case ${index + 1}: error - ${error.message}`);
            }
        });

    } catch (error) {
        console.error("Error:", error.message);
        process.exit(1);
    }
}

main().catch(console.error);