// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it, vi, beforeEach, afterEach } from 'vitest'
import { send_rpc_request, __version__ } from '../send-rpc-request'
import http from 'http'
import https from 'https'

// Mock the modules
vi.mock('http')
vi.mock('https')

describe('send_rpc_request', () => {
  let mockHttpRequest: any
  let mockHttpsRequest: any
  let mockReq: any
  let mockRes: any

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks()

    // Mock HTTP request
    mockReq = {
      write: vi.fn(),
      end: vi.fn(),
      on: vi.fn(),
      destroy: vi.fn(),
    }

    mockRes = {
      on: vi.fn(),
      statusCode: 200,
    }

    mockHttpRequest = vi.fn(() => mockReq)
    mockHttpsRequest = vi.fn(() => mockReq)

    vi.mocked(http).request = mockHttpRequest
    vi.mocked(https).request = mockHttpsRequest
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('HTTP requests', () => {
    it('should make HTTP request with correct parameters', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      // Mock the request flow
      mockHttpRequest.mockImplementation((url, options, callback) => {
        // Call the callback with mock response
        callback(mockRes)

        // Setup response data handling
        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]

        if (dataCallback) dataCallback(Buffer.from('{"result": "success"}', 'utf8'))
        if (endCallback) endCallback()

        return mockReq
      })

      const result = await send_rpc_request(endpoint, path, payload)

      expect(mockHttpRequest).toHaveBeenCalledWith(
        new URL(path, endpoint),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'User-Agent': `dstack-sdk-js/${__version__}`,
          })
        }),
        expect.any(Function)
      )

      expect(mockReq.write).toHaveBeenCalledWith(payload)
      expect(mockReq.end).toHaveBeenCalled()
      expect(result).toEqual({ result: 'success' })
    })

    it('should make HTTPS request with correct parameters', async () => {
      const endpoint = 'https://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      // Mock the request flow
      mockHttpsRequest.mockImplementation((url, options, callback) => {
        callback(mockRes)

        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]

        if (dataCallback) dataCallback(Buffer.from('{"result": "success"}', 'utf8'))
        if (endCallback) endCallback()

        return mockReq
      })

      const result = await send_rpc_request(endpoint, path, payload)

      expect(mockHttpsRequest).toHaveBeenCalled()
      expect(result).toEqual({ result: 'success' })
    })

    it('should handle HTTP request errors', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      mockHttpRequest.mockImplementation(() => {
        // Set up error callback immediately
        mockReq.on.mockImplementation((event, callback) => {
          if (event === 'error') {
            setTimeout(() => callback(new Error('connection failed')), 0)
          }
        })
        return mockReq
      })

      await expect(send_rpc_request(endpoint, path, payload)).rejects.toThrow('connection failed')
    })

    it('should report a non-2xx with its status and the prpc error text', async () => {
      mockRes.statusCode = 404
      mockHttpRequest.mockImplementation((url, options, callback) => {
        callback(mockRes)

        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]

        if (dataCallback) dataCallback(Buffer.from('{"error": "Service not found: GetKeyX"}', 'utf8'))
        if (endCallback) endCallback()

        return mockReq
      })

      await expect(send_rpc_request('http://localhost:3000', '/GetKeyX', '{}'))
        .rejects.toThrow('HTTP 404: Service not found: GetKeyX')
    })

    it('should report a non-2xx with a bounded snippet when the body is not JSON', async () => {
      // What a pre-0.6 agent answers a `/v1` call with: no `error` field, and a
      // whole page of it. Without the status this reads as a parse failure.
      const page = `<!DOCTYPE html>${'<p>not found</p>'.repeat(200)}`
      mockRes.statusCode = 404
      mockHttpRequest.mockImplementation((url, options, callback) => {
        callback(mockRes)

        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]

        if (dataCallback) dataCallback(Buffer.from(page, 'utf8'))
        if (endCallback) endCallback()

        return mockReq
      })

      const error = await send_rpc_request('http://localhost:3000', '/v1/Version', '{}')
        .catch((err: Error) => err)
      expect(error).toBeInstanceOf(Error)
      expect((error as Error).message).toContain('HTTP 404: <!DOCTYPE html>')
      expect((error as Error).message.length).toBeLessThan(page.length)
      expect((error as Error).message.endsWith('...')).toBe(true)
    })

    it('should handle invalid JSON response', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      mockHttpRequest.mockImplementation((url, options, callback) => {
        callback(mockRes)

        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]

        if (dataCallback) dataCallback(Buffer.from('invalid json', 'utf8'))
        if (endCallback) endCallback()

        return mockReq
      })

      await expect(send_rpc_request(endpoint, path, payload)).rejects.toThrow('failed to parse response')
    })
  })

  describe('timeout functionality', () => {
    it('should use default timeout of 30 seconds', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      // Mock setTimeout to capture timeout value
      const originalSetTimeout = global.setTimeout
      const mockSetTimeout = vi.fn(() => 123)
      // @ts-ignore
      global.setTimeout = mockSetTimeout

      // Don't actually complete the request
      mockHttpRequest.mockImplementation(() => mockReq)

      const promise = send_rpc_request(endpoint, path, payload)

      expect(mockSetTimeout).toHaveBeenCalledWith(expect.any(Function), 30_000)

      global.setTimeout = originalSetTimeout
    })

    it('should use custom timeout when provided', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'
      const customTimeout = 5000

      const originalSetTimeout = global.setTimeout
      const mockSetTimeout = vi.fn(() => 123)
      // @ts-ignore
      global.setTimeout = mockSetTimeout

      mockHttpRequest.mockImplementation(() => mockReq)

      const promise = send_rpc_request(endpoint, path, payload, customTimeout)

      expect(mockSetTimeout).toHaveBeenCalledWith(expect.any(Function), customTimeout)

      global.setTimeout = originalSetTimeout
    })

    // The timeout *message* is pinned in `send-rpc-request.unix.test.ts`,
    // against a real socket that accepts and never answers. Stubbing
    // `setTimeout` here would run the callback before the abort listener is
    // registered -- an ordering that cannot happen at runtime, and one that
    // made the previous version of this test pass against a transport where
    // `request timed out` was unreachable.
  })

  describe('abort functionality', () => {
    it('should cleanup properly on successful requests', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      mockHttpRequest.mockImplementation((url, options, callback) => {
        callback(mockRes)

        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]

        if (dataCallback) dataCallback(Buffer.from('{"result": "success"}', 'utf8'))
        if (endCallback) endCallback()

        return mockReq
      })

      const result = await send_rpc_request(endpoint, path, payload)
      expect(result).toEqual({ result: 'success' })
    })
  })

  describe('safe resolution/rejection', () => {
    it('should not resolve/reject multiple times', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      mockHttpRequest.mockImplementation((url, options, callback) => {
        callback(mockRes)

        // Setup multiple data and end events
        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]

        setTimeout(() => {
          if (dataCallback) dataCallback(Buffer.from('{"result": "success"}', 'utf8'))
          if (endCallback) {
            endCallback() // First end
            endCallback() // Second end - should be ignored
          }
        }, 10)

        return mockReq
      })

      const result = await send_rpc_request(endpoint, path, payload)
      expect(result).toEqual({ result: 'success' })
    })
  })
})
