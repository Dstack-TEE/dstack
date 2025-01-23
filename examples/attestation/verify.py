"""
This is an example script of how to do remote attestation for Dstack Applications.

Dependencies:
- Dstack OS Image: Can be built from source or downloaded from https://github.com/Dstack-TEE/dstack/releases/tag/dev-v0.4.0.0 for the image used in this demo.
- dcap-qvl: Phala's TDX/SGX Quote Verification tool (install with `cargo install dcap-qvl-cli`)
- dstack-mr: Tool for calculating expected measurement values for Dstack Base Images, install with `go install github.com/kvinwang/dstack-mr@latest`

Example usage is provided in the __main__ section.
"""

import hashlib
import json
from typing import Dict, Any
import tempfile
import subprocess
import os

INIT_MR = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

def replay_rtmr(history: list[str]):
    """
    Replay the RTMR history to calculate the final RTMR value.
    """
    if len(history) == 0:
        return INIT_MR
    mr = bytes.fromhex(INIT_MR)
    for content in history:
        # mr = sha384(concat(mr, content))
        # if content is shorter than 48 bytes, pad it with zeros
        content = bytes.fromhex(content)
        if len(content) < 48:
            content = content.ljust(48, b'\0')
        mr = hashlib.sha384(mr + content).digest()
    return mr.hex()


class DstackTdxQuote:
    quote: str
    event_log: str
    verified_quote: Dict[str, Any]
    parsed_event_log: list[Dict[str, Any]]
    app_id: str
    compose_hash: str
    instance_id: str
    key_provider: str

    def __init__(self, quote: str, event_log: str):
        """
        Initialize the DstackTdxQuote object.
        """
        self.quote = bytes.fromhex(quote)
        self.event_log = event_log
        self.parsed_event_log = json.loads(self.event_log)
        self.extract_info_from_event_log()
    
    def extract_info_from_event_log(self):
        """
        Extract the app ID, compose hash, instance ID, and key provider from the event log.
        """
        for event in self.parsed_event_log:
            if event.get('event') == 'app-id':
                self.app_id = event.get('event_payload', '')
            elif event.get('event') == 'compose-hash':
                self.compose_hash = event.get('event_payload', '')
            elif event.get('event') == 'instance-id':
                self.instance_id = event.get('event_payload', '')
            elif event.get('event') == 'key-provider':
                self.key_provider = bytes.fromhex(event.get('event_payload', '')).decode('utf-8')
    
    def mrs(self) -> Dict[str, str]:
        """
        Get the MRs from the verified quote.
        """
        report = self.verified_quote.get('report', {})
        if 'TD10' in report:
            return report['TD10']
        elif 'TD15' in report:
            return report['TD15']
        else:
            raise ValueError("No TD10 or TD15 report found in the quote")

    def verify(self):
        """
        Verify the TDX quote using dcap-qvl command.
        Returns True if verification succeeds, False otherwise.
        """

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(self.quote)
            temp_path = temp_file.name

        try:
            result = subprocess.run(
                ["dcap-qvl", "verify", temp_path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise ValueError(f"dcap-qvl verify failed with return code {result.returncode}")
            self.verified_quote = json.loads(result.stdout)
        finally:
            os.unlink(temp_path)

    def validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Validate an event's digest according to the Rust implementation.
        Returns True if the event is valid, False otherwise.
        """
        # Skip validation for non-IMR3 events for now
        if event.get('imr') != 3:
            return True
            
        # Calculate digest using sha384(type:event:payload)
        event_type = event.get('event_type', 0)
        event_name = event.get('event', '')
        event_payload = bytes.fromhex(event.get('event_payload', ''))
        
        if isinstance(event_payload, str):
            event_payload = event_payload.encode()
            
        hasher = hashlib.sha384()
        hasher.update(event_type.to_bytes(4, byteorder='little'))
        hasher.update(b':')
        hasher.update(event_name.encode())
        hasher.update(b':')
        hasher.update(event_payload)
        
        calculated_digest = hasher.digest().hex()
        return calculated_digest == event.get('digest')

    def replay_rtmrs(self) -> Dict[int, str]:
        rtmrs = {}
        for idx in range(4):
            history = []
            for event in self.parsed_event_log:
                if event.get('imr') == idx:
                    # Only add digest to history if event is valid
                    if self.validate_event(event):
                        history.append(event['digest'])
                    else:
                        raise ValueError(f"Invalid event digest found in IMR {idx}")
            rtmrs[idx] = replay_rtmr(history)
        return rtmrs


def sha256_hex(data: str) -> str:
    """
    Calculate the SHA256 hash of the given data.
    """
    return hashlib.sha256(data.encode()).hexdigest()


if __name__ == "__main__":
    vcpus = '1'
    memory = '1G'

    print('Pre-calculated RTMRs')
    result = subprocess.run(
        ["dstack-mr", "-cpu", vcpus, "-memory", memory, "-json", "-metadata", "images/dstack-dev-0.4.0/metadata.json"],
        capture_output=True,
        text=True
    )
    expected_mrs = json.loads(result.stdout)
    print(json.dumps(expected_mrs, indent=2))

    report = json.load(open('report.json'))
    quote = DstackTdxQuote(report['quote'], report['event_log'])
    quote.verify()
    print("Quote verified")
    verified_mrs = quote.mrs()
    show_mrs = {
        "mrtd": verified_mrs['mr_td'],
        "rtmr0": verified_mrs['rt_mr0'],
        "rtmr1": verified_mrs['rt_mr1'],
        "rtmr2": verified_mrs['rt_mr2'],
        "rtmr3": verified_mrs['rt_mr3'],
        "report_data": verified_mrs['report_data'],
    }
    print(json.dumps(show_mrs, indent=2))

    assert verified_mrs['mr_td'] == expected_mrs['mrtd'], f"MRTD mismatch: {verified_mrs['mr_td']} != {expected_mrs['mrtd']}"
    assert verified_mrs['rt_mr0'] == expected_mrs['rtmr0'], f"RTMR0 mismatch: {verified_mrs['rt_mr0']} != {expected_mrs['rtmr0']}"
    assert verified_mrs['rt_mr1'] == expected_mrs['rtmr1'], f"RTMR1 mismatch: {verified_mrs['rt_mr1']} != {expected_mrs['rtmr1']}"
    assert verified_mrs['rt_mr2'] == expected_mrs['rtmr2'], f"RTMR2 mismatch: {verified_mrs['rt_mr2']} != {expected_mrs['rtmr2']}"

    replayed_mrs = quote.replay_rtmrs()
    print("Replay RTMRs")
    print(json.dumps(replayed_mrs, indent=2))

    assert replayed_mrs[3] == verified_mrs['rt_mr3'], f"RTMR3 mismatch: {replayed_mrs[3]} != {verified_mrs['rt_mr3']}"

    expected_compose_hash = sha256_hex(open('app-compose.json').read())
    assert quote.compose_hash == expected_compose_hash, f"Compose hash mismatch: {quote.compose_hash} != {expected_compose_hash}"

    print(f"App ID: {quote.app_id}")
    print(f"Compose Hash: {quote.compose_hash}")
    print(f"Instance ID: {quote.instance_id}")
    print(f"Key Provider: {quote.key_provider}")
