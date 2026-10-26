// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// The unix-socket transport, against real sockets rather than mocks.
//
// Its sibling file mocks `http`/`https` to assert how the request is built.
// This one cannot: the defects it pins are in how a *response* is read, and a
// mock that hands the client a whole response as one string is exactly the
// fixture that hid them. Both bugs below were invisible to an ASCII fixture and
// both were live in a released transport.

import { expect, describe, it, afterEach } from 'vitest'
import { send_rpc_request } from '../send-rpc-request'
import net from 'net'
import fs from 'fs'
import os from 'os'
import path from 'path'

describe('unix socket transport', () => {
  const servers: net.Server[] = []
  const socketPaths: string[] = []
  const connections: net.Socket[] = []

  afterEach(async () => {
    // Before closing: `server.close()` waits on live connections, and these
    // servers deliberately hold theirs open the way a real agent does.
    connections.splice(0).forEach(connection => connection.destroy())
    await Promise.all(
      servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))),
    )
    socketPaths.splice(0).forEach(socketPath => {
      try {
        fs.unlinkSync(socketPath)
      } catch {
        // Already gone with the server.
      }
    })
  })

  /**
   * A server that answers every request with `status` and `body`.
   *
   * It keeps the connection open afterwards, which is what a real agent does --
   * dstack ships `keep_alive = 10` in every Rocket config. Closing here would
   * paper over a client that never decides the body is complete, since the
   * close would end the response for it.
   *
   * `writes` splits the body into chosen chunks, to place a TCP boundary where
   * a test needs one.
   */
  async function serve(
    status: string,
    body: string,
    writes: Buffer[] | null = null,
  ): Promise<string> {
    const socketPath = path.join(
      os.tmpdir(),
      `dstack-rpc-${process.pid}-${socketPaths.length}-${Math.random().toString(36).slice(2)}.sock`,
    )
    socketPaths.push(socketPath)

    const server = net.createServer(connection => {
      connections.push(connection)
      connection.on('error', () => {
        // A client that gives up resets the connection; nothing to do.
      })
      connection.once('data', () => {
        const payload = Buffer.from(body, 'utf8')
        connection.write(
          `HTTP/1.1 ${status}\r\nContent-Type: application/json\r\nContent-Length: ${payload.length}\r\n\r\n`,
        )
        for (const chunk of writes ?? [payload]) {
          connection.write(chunk)
        }
      })
    })
    servers.push(server)
    await new Promise<void>(resolve => server.listen(socketPath, () => resolve()))
    return socketPath
  }

  /** A server that accepts the connection and then never answers. */
  async function serveSilent(): Promise<string> {
    const socketPath = path.join(
      os.tmpdir(),
      `dstack-rpc-${process.pid}-${socketPaths.length}-${Math.random().toString(36).slice(2)}.sock`,
    )
    socketPaths.push(socketPath)

    const server = net.createServer(connection => {
      connections.push(connection)
      connection.on('error', () => {
        // The client aborts on timeout, which arrives here as a reset.
      })
      // Deliberately never answers.
    })
    servers.push(server)
    await new Promise<void>(resolve => server.listen(socketPath, () => resolve()))
    return socketPath
  }

  /**
   * `Content-Length` is a byte count; a JS string's `.length` is UTF-16 code
   * units. The transport this replaced compared the two, so for any body with a
   * non-ASCII character the units stayed below the bytes forever and the client
   * never decided the response was over -- it waited out the agent's keep-alive
   * instead. One accented character in an app-compose comment was enough to
   * turn `info()` into a ten-second call and `isReachable()` into `false` for a
   * healthy agent.
   */
  it('returns a multi-byte body promptly rather than waiting out keep-alive', async () => {
    const socketPath = await serve('200 OK', JSON.stringify({ note: 'café ☕ 日本語' }))

    const started = Date.now()
    const result = await send_rpc_request<{ note: string }>(socketPath, '/Info', '{}', 5000)

    expect(result.note).toBe('café ☕ 日本語')
    expect(Date.now() - started).toBeLessThan(1000)
  })

  /**
   * Appending a Buffer to a string decodes that chunk alone, so a UTF-8
   * sequence split across two TCP reads decodes to a replacement character on
   * each side -- and the call still resolves, handing back corrupted data
   * rather than failing. `info()`'s app-compose payload routinely spans reads.
   */
  it('does not corrupt a UTF-8 sequence split across two reads', async () => {
    const body = JSON.stringify({ note: 'aaa日bbb' })
    const payload = Buffer.from(body, 'utf8')
    const cut = payload.indexOf(Buffer.from('日', 'utf8')) + 1
    const socketPath = await serve('200 OK', body, [
      payload.subarray(0, cut),
      payload.subarray(cut),
    ])

    const result = await send_rpc_request<{ note: string }>(socketPath, '/Info', '{}', 5000)

    expect(result.note).toBe('aaa日bbb')
    expect(result.note).not.toContain('�')
  })

  it('reports a non-2xx with its status and the prpc error text', async () => {
    const socketPath = await serve(
      '404 Not Found',
      JSON.stringify({ error: 'Service not found: GetKeyX' }),
    )

    await expect(send_rpc_request(socketPath, '/GetKeyX', '{}', 5000)).rejects.toThrow(
      'HTTP 404: Service not found: GetKeyX',
    )
  })

  /**
   * A timeout has to *say* it timed out. `abort()` fires its listener
   * synchronously, so aborting before rejecting let `request aborted` win the
   * race and the timeout message was unreachable -- leaving `isReachable()`
   * unable to distinguish a hung agent from any other failure.
   */
  it('reports a hung agent as a timeout rather than as an abort', async () => {
    const socketPath = await serveSilent()

    await expect(send_rpc_request(socketPath, '/Info', '{}', 200)).rejects.toThrow(
      'request timed out',
    )
  })

  it('rejects when the socket does not exist', async () => {
    const missing = path.join(os.tmpdir(), 'dstack-rpc-does-not-exist.sock')

    await expect(send_rpc_request(missing, '/Version', '{}', 5000)).rejects.toThrow()
  })
})
