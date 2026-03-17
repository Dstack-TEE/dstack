// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Serde contract tests: verify that TypeScript types correctly
 * parse/produce the same JSON fixtures used by the Rust KMS tests.
 *
 * Direction-aware:
 * - BootInfo:       KMS→auth-eth  → TS is the consumer  → test deserialization
 * - BootResponse:   auth-eth→KMS  → TS is the producer  → test serialization
 * - PolicyResponse: auth-eth→KMS  → TS is the producer  → test serialization
 */

import { BootInfo, BootResponse, PolicyResponse } from '../src/types';
import * as fs from 'fs';
import * as path from 'path';

const FIXTURES_DIR = path.resolve(__dirname, '../../tests/fixtures');

describe('Serde contract tests (shared fixtures)', () => {
  describe('BootInfo (KMS→auth-eth: TS deserializes)', () => {
    it('should deserialize the shared fixture produced by Rust', () => {
      const json = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'boot_info.json'), 'utf8'));
      const info: BootInfo = json;
      // Verify all required fields are accessible after deserialization
      expect(typeof info.mrAggregated).toBe('string');
      expect(typeof info.osImageHash).toBe('string');
      expect(typeof info.mrSystem).toBe('string');
      expect(typeof info.appId).toBe('string');
      expect(typeof info.composeHash).toBe('string');
      expect(typeof info.instanceId).toBe('string');
      expect(typeof info.deviceId).toBe('string');
      expect(typeof info.tcbStatus).toBe('string');
      expect(Array.isArray(info.advisoryIds)).toBe(true);
      expect(info.tcbStatus).toBe('UpToDate');
      expect(info.advisoryIds).toEqual(['INTEL-SA-00001']);
    });

    it('should contain all fields expected by the server schema', () => {
      const json = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'boot_info.json'), 'utf8'));
      const requiredFields = ['mrAggregated', 'osImageHash', 'appId', 'composeHash', 'instanceId', 'deviceId'];
      for (const field of requiredFields) {
        expect(json).toHaveProperty(field);
      }
    });
  });

  describe('BootResponse (auth-eth→KMS: TS serializes)', () => {
    it('should produce JSON matching the shared fixture consumed by Rust', () => {
      const fixture = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'boot_response.json'), 'utf8'));
      // Construct the response as auth-eth would
      const resp: BootResponse = {
        isAllowed: true,
        gatewayAppId: '0x1234567890abcdef1234567890abcdef12345678',
        reason: '',
      };
      expect(JSON.parse(JSON.stringify(resp))).toEqual(fixture);
    });
  });

  describe('PolicyResponse (auth-eth→KMS: TS serializes)', () => {
    it('should produce JSON matching the shared fixture consumed by Rust', () => {
      const fixture = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'policy_response.json'), 'utf8'));
      // Construct the response as auth-eth would
      const resp: PolicyResponse = {
        tcbPolicy: '{"version":1,"intel_qal":[]}',
      };
      expect(JSON.parse(JSON.stringify(resp))).toEqual(fixture);
    });
  });
});
