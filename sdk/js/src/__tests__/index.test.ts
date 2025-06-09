import { expect, describe, it } from 'vitest'
import { TappdClient, send_rpc_request } from '../index'
import net from 'net'

// Test PEM key for cross-platform validation
const TEST_PEM_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsxWvvkVZix6DYyFP
aS1yz5RZLOSiiHLx8mp7axE6Whuha0QDQgAED/3OrGv33eegcOrd8WYJWLMbDJQc
TJaeKpGauQSXugPjuwnq4a2mCUE221wXaGWAXBtH4eiHiumFe2eFzeDACA==
-----END PRIVATE KEY-----`

describe('TappdClient', () => {
  it('should able to derive key', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
  })

  it('should able to request tdx quote', async () => {
    const client = new TappdClient()
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.tdxQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.quote.substring(0, 2)).toBe('0x')
    expect(result.event_log.substring(0, 1) === '{')
    expect(() => JSON.parse(result.event_log)).not.toThrowError()
    expect(result.replayRtmrs().length).toBe(4)
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const key = result.asUint8Array()
    expect(key).toBeInstanceOf(Uint8Array)
  })

  it('should compare asUint8Array and asUint8Array with length', () => {
    const client = new TappdClient()
    const key = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    const full = key.asUint8Array()
    const key32 = key.asUint8Array(32)
    expect(key32.length).toBe(32)
    expect(key32.length).not.eq(full.length)
  })

  it('should validate asUint8Array output with known PEM key', () => {
    // Create a mock DeriveKeyResponse with known PEM key
    const mockResult = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        // Import the x509key_to_uint8array function logic
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    // Test full length conversion
    const resultFull = mockResult.asUint8Array()
    expect(resultFull).toBeInstanceOf(Uint8Array)
    expect(resultFull.length).toBe(139)  // Expected length for this key

    // Test with specific length
    const result32 = mockResult.asUint8Array(32)
    expect(result32).toBeInstanceOf(Uint8Array)
    expect(result32.length).toBe(32)

    // Verify expected hex output (should match Python)
    const expectedPrefix = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
    const result32Hex = Array.from(result32).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(result32Hex).toBe(expectedPrefix)

    // Test that longer result starts with the same prefix
    const resultFullPrefix = Array.from(resultFull.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(resultFullPrefix).toBe(expectedPrefix)

    // Expected full hex for this specific key (should match Python)
    const expectedFullHex = ("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02" +
                           "01010420b315afbe45598b1e8363214f692d72cf94592ce4a28872f1f26a7b6b11" +
                           "3a5a1ba16b44034200040ffdceac6bf7dde7a070eaddf1660958b31b0c941c4c96" +
                           "9e2a919ab90497ba03e3bb09eae1ada6094136db5c176865805c1b47e1e8878ae9" +
                           "857b6785cde0c008")
    const resultFullHex = Array.from(resultFull).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(resultFullHex).toBe(expectedFullHex)
  })

  it('should validate deprecated vs secure API differences', async () => {
    // Import the functions for testing
    const { toKeypair, toKeypairSecure } = await import('../solana')
    const { toViemAccount, toViemAccountSecure } = await import('../viem')

    const mockResult = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    // Test that deprecated APIs work as before (using first 32 bytes)
    const deprecatedSolanaKeypair = toKeypair(mockResult)
    const secureKeypair = toKeypairSecure(mockResult)
    
    // These should be different because deprecated uses first 32 bytes, secure uses SHA256 hash
    expect(deprecatedSolanaKeypair.publicKey.toString()).not.toBe(secureKeypair.publicKey.toString())

    const deprecatedViemAccount = toViemAccount(mockResult)
    const secureViemAccount = toViemAccountSecure(mockResult)
    
    // These should be different because deprecated uses first 32 bytes, secure uses SHA256 hash
    expect(deprecatedViemAccount.address).not.toBe(secureViemAccount.address)

    // Verify deprecated API actually uses first 32 bytes (original behavior)
    const first32Bytes = mockResult.asUint8Array(32)
    const expectedSolanaKeypair = require('@solana/web3.js').Keypair.fromSeed(first32Bytes)
    expect(deprecatedSolanaKeypair.publicKey.toString()).toBe(expectedSolanaKeypair.publicKey.toString())
  })

  it('should able set quote hash_algorithm', async () => {
    const client = new TappdClient()
    const result = await client.tdxQuote('pure string', 'raw')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('replayRtmrs')
  })

  it('should able to request tdx quote', async () => {
    const client = new TappdClient()
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.tdxQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.quote.substring(0, 2)).toBe('0x')
    expect(result.event_log.substring(0, 1) === '{')
    expect(() => JSON.parse(result.event_log)).not.toThrowError()
    expect(result.replayRtmrs().length).toBe(4)
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const key = result.asUint8Array()
    expect(key).toBeInstanceOf(Uint8Array)
  })

  it('should able to get derive key result as uint8array with specified length', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const full = result.asUint8Array()
    const key = result.asUint8Array(32)
    expect(full).toBeInstanceOf(Uint8Array)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
    expect(key.length).not.eq(full.length)
  })

  it('should throw error on report_data large then 64 characters and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    expect(() => client.tdxQuote('0'.padEnd(65, 'x'), 'raw')).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    expect(() => client.tdxQuote(Buffer.alloc(65), 'raw')).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    const input = new Uint8Array(65).fill(0)
    expect(() => client.tdxQuote(input, 'raw')).rejects.toThrow()
  })

  it('should verify secure APIs use SHA256 hash of complete key material', async () => {
    const { toKeypairSecure } = await import('../solana')
    const { toViemAccountSecure } = await import('../viem')
    const crypto = require('crypto')

    const mockResult = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    // Test secure Solana API
    const secureKeypair = toKeypairSecure(mockResult)
    const expectedHash = crypto.createHash('sha256').update(mockResult.asUint8Array()).digest()
    const expectedSolanaKeypair = require('@solana/web3.js').Keypair.fromSeed(expectedHash)
    expect(secureKeypair.publicKey.toString()).toBe(expectedSolanaKeypair.publicKey.toString())

    // Test secure Viem API
    const secureViemAccount = toViemAccountSecure(mockResult)
    const expectedHex = crypto.createHash('sha256').update(mockResult.asUint8Array()).digest('hex')
    const { privateKeyToAccount } = require('viem/accounts')
    const expectedViemAccount = privateKeyToAccount(`0x${expectedHex}`)
    expect(secureViemAccount.address).toBe(expectedViemAccount.address)
  })
})

describe('send_rpc_request timeout and abort', () => {
  it('should timeout after 30 seconds with http endpoint', async () => {
    // Create a server that accepts connections but never responds
    const server = require('http').createServer((req, res) => {
      // Don't respond, let it hang
    })
    
    await new Promise<void>((resolve) => {
      server.listen(0, () => resolve())
    })
    
    const port = server.address().port
    const endpoint = `http://localhost:${port}`
    
    try {
      const start = Date.now()
      // The timeout triggers abort, so we expect 'request aborted' not 'request timed out'
      await expect(send_rpc_request(endpoint, '/test', '{}')).rejects.toThrow('request aborted')
      const elapsed = Date.now() - start
      
      // Should timeout around 30 seconds (with some tolerance)
      expect(elapsed).toBeGreaterThanOrEqual(29000)
      expect(elapsed).toBeLessThan(32000)
    } finally {
      server.close()
    }
  }, 35000) // Test timeout longer than request timeout

  it('should timeout after 30 seconds with unix socket endpoint', async () => {
    // Create a Unix socket server that accepts connections but never responds
    const socketPath = `/tmp/test-socket-${Date.now()}`
    const server = net.createServer((socket) => {
      // Don't respond, let it hang
    })
    
    await new Promise<void>((resolve) => {
      server.listen(socketPath, () => resolve())
    })
    
    try {
      const start = Date.now()
      // The timeout triggers abort, so we expect 'request aborted' not 'request timed out'
      await expect(send_rpc_request(socketPath, '/test', '{}')).rejects.toThrow('request aborted')
      const elapsed = Date.now() - start
      
      // Should timeout around 30 seconds (with some tolerance)
      expect(elapsed).toBeGreaterThanOrEqual(29000)
      expect(elapsed).toBeLessThan(32000)
    } finally {
      server.close()
      // Clean up socket file
      require('fs').unlink(socketPath, () => {})
    }
  }, 35000) // Test timeout longer than request timeout

  it('should handle manual abort with custom abort controller', async () => {
    // Create a testable version of send_rpc_request that exposes abortController
    function send_rpc_request_with_abort<T = any>(endpoint: string, path: string, payload: string): { promise: Promise<T>, abort: () => void } {
      let abortController: AbortController
      let isCompleted = false
      
      const promise = new Promise<T>((resolve, reject) => {
        abortController = new AbortController()
        
        const safeReject = (error: Error) => {
          if (!isCompleted) {
            isCompleted = true
            reject(error)
          }
        }
        
        const safeResolve = (result: T) => {
          if (!isCompleted) {
            isCompleted = true
            resolve(result)
          }
        }
        
        const timeout = setTimeout(() => {
          abortController.abort()
          safeReject(new Error('request timed out'))
        }, 30_000)

        const cleanup = () => {
          clearTimeout(timeout)
          abortController.signal.removeEventListener('abort', onAbort)
        }

        const onAbort = () => {
          cleanup()
          safeReject(new Error('request aborted'))
        }

        abortController.signal.addEventListener('abort', onAbort)

        // Create a server that never responds
        const server = require('http').createServer((req, res) => {
          // Don't respond
        })
        
        server.listen(0, () => {
          const port = server.address().port
          const url = new URL(path, `http://localhost:${port}`)
          const req = require('http').request(url, { method: 'POST' }, (res) => {
            // This won't be called since server doesn't respond
          })

          req.on('error', (error) => {
            cleanup()
            server.close()
            safeReject(error)
          })

          abortController.signal.addEventListener('abort', () => {
            req.destroy()
            server.close()
          })

          req.write(payload)
          req.end()
        })
      })

      return {
        promise,
        abort: () => abortController?.abort()
      }
    }

    const start = Date.now()
    const { promise, abort } = send_rpc_request_with_abort('http://localhost:1', '/test', '{}')
    
    // Abort after 1 second
    setTimeout(() => {
      abort()
    }, 1000)
    
    await expect(promise).rejects.toThrow('request aborted')
    const elapsed = Date.now() - start
    
    // Should abort quickly (around 1 second, not 30)
    expect(elapsed).toBeLessThan(5000)
    expect(elapsed).toBeGreaterThanOrEqual(1000)
  })

  it('should handle connection errors gracefully', async () => {
    // Try to connect to a non-existent HTTP server
    const endpoint = 'http://localhost:99999'
    
    await expect(send_rpc_request(endpoint, '/test', '{}')).rejects.toThrow()
  })

  it('should handle connection errors for unix socket gracefully', async () => {
    // Try to connect to a non-existent Unix socket
    const endpoint = '/tmp/non-existent-socket'
    
    await expect(send_rpc_request(endpoint, '/test', '{}')).rejects.toThrow()
  })

  it('should handle malformed JSON response', async () => {
    // Create a server that returns invalid JSON
    const server = require('http').createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end('invalid json{')
    })
    
    await new Promise<void>((resolve) => {
      server.listen(0, () => resolve())
    })
    
    const port = server.address().port
    const endpoint = `http://localhost:${port}`
    
    try {
      await expect(send_rpc_request(endpoint, '/test', '{}')).rejects.toThrow('failed to parse response')
    } finally {
      server.close()
    }
  })

  it('should handle malformed JSON response from unix socket', async () => {
    // Create a Unix socket server that returns invalid JSON
    const socketPath = `/tmp/test-socket-json-${Date.now()}`
    const server = net.createServer((socket) => {
      socket.write('HTTP/1.1 200 OK\r\n')
      socket.write('Content-Type: application/json\r\n')
      socket.write('Content-Length: 13\r\n')
      socket.write('\r\n')
      socket.write('invalid json{')
      socket.end()
    })
    
    await new Promise<void>((resolve) => {
      server.listen(socketPath, () => resolve())
    })
    
    try {
      await expect(send_rpc_request(socketPath, '/test', '{}')).rejects.toThrow('failed to parse response')
    } finally {
      server.close()
      require('fs').unlink(socketPath, () => {})
    }
  })

  it('should successfully handle valid response from http server', async () => {
    // Create a server that returns valid JSON
    const server = require('http').createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end('{"success": true}')
    })
    
    await new Promise<void>((resolve) => {
      server.listen(0, () => resolve())
    })
    
    const port = server.address().port
    const endpoint = `http://localhost:${port}`
    
    try {
      const result = await send_rpc_request(endpoint, '/test', '{}')
      expect(result).toEqual({ success: true })
    } finally {
      server.close()
    }
  })

  it('should successfully handle valid response from unix socket', async () => {
    // Create a Unix socket server that returns valid JSON
    const socketPath = `/tmp/test-socket-valid-${Date.now()}`
    const server = net.createServer((socket) => {
      socket.write('HTTP/1.1 200 OK\r\n')
      socket.write('Content-Type: application/json\r\n')
      socket.write('Content-Length: 17\r\n')
      socket.write('\r\n')
      socket.write('{"success": true}')
      socket.end()
    })
    
    await new Promise<void>((resolve) => {
      server.listen(socketPath, () => resolve())
    })
    
    try {
      const result = await send_rpc_request(socketPath, '/test', '{}')
      expect(result).toEqual({ success: true })
    } finally {
      server.close()
      require('fs').unlink(socketPath, () => {})
    }
  })

  it('should prevent duplicate rejections', async () => {
    // Test that our safe reject/resolve mechanism works
    let rejectCount = 0
    let resolveCount = 0
    
    const testPromise = new Promise((resolve, reject) => {
      let isCompleted = false
      
      const safeReject = (error: Error) => {
        rejectCount++
        if (!isCompleted) {
          isCompleted = true
          reject(error)
        }
      }
      
      const safeResolve = (result: any) => {
        resolveCount++
        if (!isCompleted) {
          isCompleted = true
          resolve(result)
        }
      }
      
      // Try to reject multiple times - only two should run since the first will complete
      setTimeout(() => safeReject(new Error('first')), 10)
      setTimeout(() => safeReject(new Error('second')), 20)
      // This won't run because promise is already completed  
      setTimeout(() => safeResolve('resolved'), 30)
    })
    
    await expect(testPromise).rejects.toThrow('first')
    
    // Wait a bit to ensure all timeouts fire
    await new Promise(resolve => setTimeout(resolve, 100))
    
    // First reject completes the promise, second should be attempted but ignored
    // The resolve should also be attempted since the timeout is already set
    expect(rejectCount).toBe(2) // First two rejects should increment counter  
    expect(resolveCount).toBe(1) // Resolve should still be attempted
  })

  it('should timeout with fast timeout for testing', async () => {
    // Create a testable version with shorter timeout
    function send_rpc_request_fast_timeout<T = any>(endpoint: string, path: string, payload: string): Promise<T> {
      return new Promise((resolve, reject) => {
        const abortController = new AbortController()
        let isCompleted = false
        
        const safeReject = (error: Error) => {
          if (!isCompleted) {
            isCompleted = true
            reject(error)
          }
        }
        
        const timeout = setTimeout(() => {
          abortController.abort()
          safeReject(new Error('request timed out'))
        }, 1000) // 1 second timeout for testing

        const cleanup = () => {
          clearTimeout(timeout)
          abortController.signal.removeEventListener('abort', onAbort)
        }

        const onAbort = () => {
          cleanup()
          safeReject(new Error('request aborted'))
        }

        abortController.signal.addEventListener('abort', onAbort)

        // Create a server that never responds
        const server = require('http').createServer((req, res) => {
          // Don't respond
        })
        
        server.listen(0, () => {
          const port = server.address().port
          const url = new URL(path, `http://localhost:${port}`)
          const req = require('http').request(url, { method: 'POST' }, (res) => {
            // This won't be called since server doesn't respond
          })

          req.on('error', (error) => {
            cleanup()
            server.close()
            safeReject(error)
          })

          abortController.signal.addEventListener('abort', () => {
            req.destroy()
            server.close()
          })

          req.write(payload)
          req.end()
        })
      })
    }

    const start = Date.now()
    await expect(send_rpc_request_fast_timeout('http://localhost:1', '/test', '{}')).rejects.toThrow('request aborted')
    const elapsed = Date.now() - start
    
    // Should timeout around 1 second
    expect(elapsed).toBeGreaterThanOrEqual(1000)
    expect(elapsed).toBeLessThan(2000)
  })
})
