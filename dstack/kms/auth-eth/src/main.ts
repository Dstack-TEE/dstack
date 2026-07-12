// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { config } from 'dotenv';
import { build } from './server';

// Load environment variables
config();

async function main() {
  try {
    const port = process.env.PORT ? parseInt(process.env.PORT) : 8000;
    const host = process.env.HOST || '127.0.0.1';

    const server = await build();
    await server.listen({ port, host });
    console.log(`Server listening on ${host}:${port}`);

    // Handle graceful shutdown
    const signals = ['SIGINT', 'SIGTERM'];
    for (const signal of signals) {
      process.on(signal, async () => {
        try {
          await server.close();
          process.exit(0);
        } catch (err) {
          console.error('Error during shutdown:', err);
          process.exit(1);
        }
      });
    }
  } catch (err) {
    console.error('Error starting server:', err);
    process.exit(1);
  }
}

main();
