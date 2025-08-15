// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it } from 'vitest'
import { getComposeHash, AppCompose } from '../get-compose-hash'

describe('Deterministic JSON Serialization', () => {
  describe('Key Sorting', () => {
    it('should sort object keys lexicographically', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        bash_script: "start.sh"
      }
      
      const compose2: AppCompose = {
        bash_script: "start.sh",
        docker_compose_file: "docker-compose.yml",
        runner: "docker-compose"
      }
      
      // Both should produce the same hash despite different key order
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })

    it('should handle nested object key sorting', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        nested_config: {
          gamma: 3.14,
          alpha: "first",
          beta: 42
        }
      } as AppCompose
      
      const compose2: AppCompose = {
        nested_config: {
          alpha: "first",
          beta: 42,
          gamma: 3.14
        },
        runner: "docker-compose"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })

    it('should handle deeply nested objects', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        config: {
          database: {
            port: 5432,
            host: "localhost",
            credentials: {
              username: "admin",
              password: "secret"
            }
          },
          cache: {
            redis: {
              url: "redis://localhost:6379",
              timeout: 1000
            }
          }
        }
      } as AppCompose
      
      const compose2: AppCompose = {
        config: {
          cache: {
            redis: {
              timeout: 1000,
              url: "redis://localhost:6379"
            }
          },
          database: {
            credentials: {
              password: "secret",
              username: "admin"
            },
            host: "localhost",
            port: 5432
          }
        },
        runner: "docker-compose"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Array Handling', () => {
    it('should preserve array order', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        items: [3, 1, 2]
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        items: [1, 2, 3]
      } as AppCompose
      
      // Different array orders should produce different hashes
      expect(getComposeHash(compose1)).not.toBe(getComposeHash(compose2))
    })

    it('should handle arrays with objects', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        services: [
          { name: "web", port: 80 },
          { name: "db", port: 5432 }
        ]
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        services: [
          { port: 80, name: "web" },
          { port: 5432, name: "db" }
        ]
      } as AppCompose
      
      // Object keys should be sorted within arrays
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Special Value Handling', () => {
    it('should convert NaN to null', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        special_value: NaN
      } as AppCompose
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64) // SHA256 hex length
    })

    it('should convert Infinity to null', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        special_value: Infinity
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        special_value: -Infinity
      } as AppCompose
      
      const compose3: AppCompose = {
        runner: "docker-compose",
        special_value: null
      }
      
      // All should produce the same hash since NaN and Infinity become null
      const hash1 = getComposeHash(compose1)
      const hash2 = getComposeHash(compose2)
      const hash3 = getComposeHash(compose3)
      
      expect(hash1).toBe(hash2)
      expect(hash2).toBe(hash3)
    })

    it('should handle undefined values', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        optional_field: undefined
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose"
      }
      
      // undefined values should be treated consistently
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Preprocessing Logic', () => {
    it('should remove docker_compose_file when runner is bash (with normalization)', () => {
      const compose: AppCompose = {
        runner: "bash",
        bash_script: "start.sh",
        docker_compose_file: "docker-compose.yml"
      }
      
      const hash = getComposeHash(compose, true)
      
      // Should be the same as compose without docker_compose_file
      const compose2: AppCompose = {
        runner: "bash",
        bash_script: "start.sh"
      }
      
      expect(hash).toBe(getComposeHash(compose2, true))
    })

    it('should remove bash_script when runner is docker-compose (with normalization)', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        bash_script: "start.sh"
      }
      
      const hash = getComposeHash(compose, true)
      
      // Should be the same as compose without bash_script
      const compose2: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      expect(hash).toBe(getComposeHash(compose2, true))
    })

    it('should remove empty pre_launch_script (with normalization)', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        pre_launch_script: ""
      }
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      expect(getComposeHash(compose1, true)).toBe(getComposeHash(compose2, true))
    })

    it('should keep non-empty pre_launch_script (with normalization)', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        pre_launch_script: "echo 'Starting...'"
      }
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      expect(getComposeHash(compose1, true)).not.toBe(getComposeHash(compose2, true))
    })
  })

  describe('UTF-8 Support', () => {
    it('should handle non-ASCII characters consistently', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        text: "你好世界",
        description: "🚀 Deploy"
      } as AppCompose
      
      const compose2: AppCompose = {
        description: "🚀 Deploy",
        runner: "docker-compose",
        text: "你好世界"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Cross-Language Compatibility Example', () => {
    it('should produce consistent hash for reference data', () => {
      // This is a reference test case that should produce the same hash
      // as equivalent implementations in Go and Python
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        text: "你好世界",
        id: "c73a3a4e-ce71-4c12-a1b7-78be1a2e48e0",
        b_number: 123,
        a_status: true,
        z_items: [3, 1, 2],
        nested: {
          gamma: 3.14,
          alpha: "first"
        }
      } as AppCompose
      
      const hash = getComposeHash(compose)
      
      // This should be a deterministic hash
      expect(hash).toHaveLength(64)
      expect(hash).toMatch(/^[a-f0-9]{64}$/)
      
      // The exact hash value depends on the specific data structure
      // but it should be consistent across runs
      const hash2 = getComposeHash(compose)
      expect(hash).toBe(hash2)
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty objects', () => {
      // @ts-expect-error - empty object is valid
      const compose: AppCompose = {}
      const hash = getComposeHash(compose)
      
      expect(hash).toHaveLength(64)
      expect(hash).toMatch(/^[a-f0-9]{64}$/)
    })

    it('should handle null values', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        optional_field: null
      } as AppCompose
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
    })

    it('should handle boolean values', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        enabled: true,
        debug: false
      } as AppCompose
      
      const compose2: AppCompose = {
        debug: false,
        enabled: true,
        runner: "docker-compose"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })

    it('should handle numeric edge cases', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        zero: 0,
        negative: -42,
        float: 3.14159,
        large: 1e10
      } as AppCompose
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
    })
  })

  describe('Determinism Verification', () => {
    it('should produce identical hashes for multiple calls', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        environment: {
          NODE_ENV: "production",
          PORT: 3000,
          DATABASE_URL: "postgres://localhost:5432/mydb"
        }
      } as AppCompose
      
      const hashes = Array.from({ length: 10 }, () => getComposeHash(compose))
      
      // All hashes should be identical
      const firstHash = hashes[0]
      expect(hashes.every(hash => hash === firstHash)).toBe(true)
    })

    it('should produce different hashes for different data', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      const compose2: AppCompose = {
        runner: "bash",
        bash_script: "start.sh"
      }
      
      expect(getComposeHash(compose1)).not.toBe(getComposeHash(compose2))
    })
  })

  describe('New AppCompose Fields', () => {
    it('should handle manifest_version and name fields', () => {
      const compose: AppCompose = {
        manifest_version: 1,
        name: "my-app",
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })

    it('should handle docker_config field', () => {
      const compose: AppCompose = {
        manifest_version: 1,
        name: "my-app",
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        docker_config: {
          registry: "docker.io",
          username: "myuser",
          token_key: "token123"
        }
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })

    it('should handle boolean flags', () => {
      const compose: AppCompose = {
        manifest_version: 1,
        name: "my-app",
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        public_logs: true,
        public_sysinfo: false,
        public_tcbinfo: true,
        kms_enabled: true,
        gateway_enabled: false,
        local_key_provider_enabled: true,
        no_instance_id: false,
        secure_time: true
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })

    it('should handle key_provider and key_provider_id fields', () => {
      const compose: AppCompose = {
        manifest_version: 1,
        name: "my-app",
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        key_provider: "kms",
        key_provider_id: "abcd1234"
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })

    it('should handle allowed_envs array', () => {
      const compose: AppCompose = {
        manifest_version: 1,
        name: "my-app",
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        allowed_envs: ["NODE_ENV", "PORT", "DATABASE_URL"]
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })

    it('should handle features array (deprecated)', () => {
      const compose: AppCompose = {
        manifest_version: 1,
        name: "my-app",
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        features: ["feature1", "feature2"]
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })
  })

  describe('Normalize Parameter', () => {
    it('should skip preprocessing when normalize=false (default)', () => {
      const compose: AppCompose = {
        runner: "bash",
        bash_script: "start.sh",
        docker_compose_file: "docker-compose.yml"
      }
      
      const hashWithoutNormalize = getComposeHash(compose)
      const hashExplicitFalse = getComposeHash(compose, false)
      
      expect(hashWithoutNormalize).toBe(hashExplicitFalse)
    })

    it('should apply preprocessing when normalize=true', () => {
      const compose: AppCompose = {
        runner: "bash",
        bash_script: "start.sh",
        docker_compose_file: "docker-compose.yml"
      }
      
      const hashWithNormalize = getComposeHash(compose, true)
      const hashWithoutNormalize = getComposeHash(compose, false)
      
      // These should be different because preprocessing is applied only with normalize=true
      expect(hashWithNormalize).not.toBe(hashWithoutNormalize)
    })

    it('should handle empty pre_launch_script differently with/without normalization', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        pre_launch_script: ""
      }
      
      const composeWithoutEmpty: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      // With normalization, empty pre_launch_script should be removed
      expect(getComposeHash(compose, true)).toBe(getComposeHash(composeWithoutEmpty, true))
      
      // Without normalization, empty pre_launch_script should remain
      expect(getComposeHash(compose, false)).not.toBe(getComposeHash(composeWithoutEmpty, false))
    })
  })

  describe('Backward Compatibility', () => {
    it('should still work with legacy bash_script and pre_launch_script', () => {
      const compose: AppCompose = {
        runner: "bash",
        bash_script: "start.sh",
        pre_launch_script: "echo 'Starting...'"
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })

    it('should maintain deterministic behavior across versions', () => {
      // A compose with both old and new fields
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        bash_script: "start.sh", // Should be removed by preprocessing when normalize=true
        features: ["legacy-feature"],
        public_logs: true,
        kms_enabled: false,
        gateway_enabled: true,
        allowed_envs: ["NODE_ENV"],
        secure_time: false
      }
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64)
    })
  })
}) 