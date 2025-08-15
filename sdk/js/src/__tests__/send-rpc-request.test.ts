// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it, vi, beforeEach, afterEach } from 'vitest'
import { send_rpc_request, __version__ } from '../send-rpc-request'
import http from 'http'
import https from 'https'
import net from 'net'

// Mock the modules
vi.mock('http')
vi.mock('https')
vi.mock('net')

describe('send_rpc_request', () => {
  let mockHttpRequest: any
  let mockHttpsRequest: any
  let mockNetConnect: any
  let mockReq: any
  let mockRes: any
  let mockClient: any

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

    // Mock net connection
    mockClient = {
      write: vi.fn(),
      end: vi.fn(),
      on: vi.fn(),
      destroy: vi.fn(),
    }

    mockNetConnect = vi.fn(() => mockClient)
    vi.mocked(net).createConnection = mockNetConnect
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
        
        if (dataCallback) dataCallback('{"result": "success"}')
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
        
        if (dataCallback) dataCallback('{"result": "success"}')
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

    it('should handle invalid JSON response', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      mockHttpRequest.mockImplementation((url, options, callback) => {
        callback(mockRes)
        
        const dataCallback = mockRes.on.mock.calls.find(call => call[0] === 'data')?.[1]
        const endCallback = mockRes.on.mock.calls.find(call => call[0] === 'end')?.[1]
        
        if (dataCallback) dataCallback('invalid json')
        if (endCallback) endCallback()
        
        return mockReq
      })

      await expect(send_rpc_request(endpoint, path, payload)).rejects.toThrow('failed to parse response')
    })
  })

    describe('Unix socket requests', () => {
    it('should call createConnection with correct parameters', () => {
      const endpoint = '/tmp/socket'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      // Mock the socket connection to never complete
      mockNetConnect.mockImplementation((options, callback) => {
        return mockClient
      })

      // Start the request but don't wait for completion
      send_rpc_request(endpoint, path, payload)

      expect(mockNetConnect).toHaveBeenCalledWith({ path: endpoint }, expect.any(Function))
    })

    it('should handle Unix socket connection errors', async () => {
      const endpoint = '/tmp/socket'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      mockNetConnect.mockImplementation(() => {
        mockClient.on.mockImplementation((event, callback) => {
          if (event === 'error') {
            setTimeout(() => callback(new Error('socket connection failed')), 0)
          }
        })
        return mockClient
      })

      await expect(send_rpc_request(endpoint, path, payload)).rejects.toThrow('socket connection failed')
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

    it('should timeout and reject with correct error message', async () => {
      const endpoint = 'http://localhost:3000'
      const path = '/api/test'
      const payload = '{"test": "data"}'

      // Mock real setTimeout to trigger timeout immediately  
      const originalSetTimeout = global.setTimeout
      // @ts-ignore
      global.setTimeout = vi.fn((callback, delay) => {
        if (delay === 1) {
          // Call timeout callback immediately for our test timeout
          callback()
          return 123 as any
        }
        return originalSetTimeout(callback, delay)
      })

      mockHttpRequest.mockImplementation(() => {
        // Never complete the request
        return mockReq
      })

      await expect(send_rpc_request(endpoint, path, payload, 1)).rejects.toThrow('request timed out')
      
      global.setTimeout = originalSetTimeout
    })
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
        
        if (dataCallback) dataCallback('{"result": "success"}')
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
          if (dataCallback) dataCallback('{"result": "success"}')
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