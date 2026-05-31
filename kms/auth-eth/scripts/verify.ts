// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { run } from "hardhat";

async function main() {
  const PROXY_ADDRESS = "0xda1d4bc372FE139d63b85f6160D2F849fFed9c10";

  try {
    // Verify the proxy contract
    console.log("\nVerifying proxy contract...");
    await run("verify:verify", {
      address: PROXY_ADDRESS,
      constructorArguments: [],
    });

    console.log("\nVerification completed successfully!");
  } catch (error) {
    console.error("Error during verification:", error);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}); 