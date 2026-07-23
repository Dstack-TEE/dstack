# Attestation 模拟 E2E 报告

命令：

```bash
cd dstack
./tests/e2e/attestation/run.sh
```

结果：**PASS (SIMULATED)**，6/6 平台通过：

- dstack TDX legacy；
- dstack TDX lite；
- GCP TDX；
- AMD SEV-SNP；
- AWS Nitro Enclave；
- AWS NitroTPM。

每个平台均满足：

```text
is_valid=true
quote_verified=true
event_log_verified=true
os_image_hash_verified=true
```

## 结论边界

该套件证明解析、证据分派、event-log replay 和 verifier 组合路径对六种格式有效。它没有连接云厂商或真实 GPU/TEE，因此 PLAT-01、PLAT-03、PLAT-05、PLAT-06 的真实性、freshness、证书链、KDS/OCSP 故障恢复等硬件断言仍为 BLOCKED/PARTIAL，不能标为真实平台 PASS。
