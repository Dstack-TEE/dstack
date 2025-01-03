#!/usr/bin/env python3
import os
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from web3 import Web3
import uvicorn
import argparse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="DStack KMS Ethereum Backend")

APP_CONTRACT_ABI = '''
[{
    "inputs": [
        {"name": "appId", "type": "bytes32"},
        {"name": "composeHash", "type": "bytes32"},
        {"name": "instanceId", "type": "bytes32"},
        {"name": "deviceId", "type": "bytes32"}
    ],
    "name": "isAppAllowed",
    "outputs": [
        {"name": "allowed", "type": "bool"},
        {"name": "reason", "type": "string"}
    ],
    "stateMutability": "view",
    "type": "function"
}]
'''

class BootInfo(BaseModel):
    mrtd: str = Field(..., description="MRTD measurement")
    app_id: str = Field(..., description="Application ID")
    compose_hash: str = Field(..., description="Compose hash")
    instance_id: str = Field(..., description="Instance ID")
    device_id: str = Field(..., description="Device ID")
    rtmr0: str = Field(..., description="RTMR0 measurement")
    rtmr1: str = Field(..., description="RTMR1 measurement")
    rtmr2: str = Field(..., description="RTMR2 measurement")
    rtmr3: str = Field(..., description="RTMR3 measurement")

class BootResponse(BaseModel):
    is_allowed: bool
    reason: str

class EthereumBackend:
    def __init__(self, rpc_url: str, kms_contract_addr: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Initialize contracts
        self.kms_contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(kms_contract_addr),
            abi=KMS_CONTRACT_ABI
        )

    def decode_hex32(self, hex_str: str) -> bytes:
        """Convert hex string to 32 bytes."""
        hex_str = hex_str.removeprefix("0x")
        return bytes.fromhex(hex_str.zfill(64))

    async def check_boot(self, boot_info: BootInfo) -> BootResponse:
        try:
            # Check KMS contract
            kms_allowed, kms_reason = self.kms_contract.functions.isAppAllowed(
                Web3.to_checksum_address(boot_info.app_id),
                self.decode_hex32(boot_info.compose_hash),
                Web3.to_checksum_address(boot_info.instance_id),
                self.decode_hex32(boot_info.device_id),
                self.decode_hex32(boot_info.mrtd),
                self.decode_hex32(boot_info.rtmr0),
                self.decode_hex32(boot_info.rtmr1),
                self.decode_hex32(boot_info.rtmr2),
                self.decode_hex32(boot_info.rtmr3)
            ).call()

            return BootResponse(is_allowed=kms_allowed, reason=kms_reason)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

# Global backend instance
backend: Optional[EthereumBackend] = None

@app.post("/", response_model=BootResponse)
async def check_boot(boot_info: BootInfo):
    if backend is None:
        raise HTTPException(status_code=500, detail="Backend not initialized")
    return await backend.check_boot(boot_info)

def main():
    global backend

    parser = argparse.ArgumentParser(description="DStack KMS Ethereum Backend")
    parser.add_argument("--eth-rpc-url", default=os.getenv("ETH_RPC_URL"), help="Ethereum RPC URL")
    parser.add_argument("--kms-contract", default=os.getenv("KMS_CONTRACT"), help="KMS contract address")
    parser.add_argument("--host", default="127.0.0.1", help="Listen host")
    parser.add_argument("--port", type=int, default=3000, help="Listen port")
    
    args = parser.parse_args()

    # Validate required arguments
    if not all([args.eth_rpc_url, args.kms_contract]):
        parser.error("Missing required arguments. Provide them via command line or environment variables.")

    # Initialize backend
    backend = EthereumBackend(args.eth_rpc_url, args.kms_contract)

    # Start server
    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
