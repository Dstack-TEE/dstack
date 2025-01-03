from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timezone, timedelta
import hashlib
import json

def generate_signed_cert(domain: str, org_name: str, issuer_cert: x509.Certificate, issuer_key: ec.EllipticCurvePrivateKey, 
                        is_ca: bool = False, path_length: int = None, valid_days: int = 365):
    """
    Generate a certificate signed by the given issuer certificate and key.
    
    Args:
        domain (str): Domain name for the certificate
        org_name (str): Organization name
        issuer_cert (x509.Certificate): Issuer's certificate
        issuer_key (ec.EllipticCurvePrivateKey): Issuer's private key
        is_ca (bool): Whether this is a CA certificate
        path_length (int): Maximum path length for CA certificates, None for unlimited
        valid_days (int): Validity period in days
        
    Returns:
        tuple: (certificate PEM, private key PEM)
    """
    # Generate key
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Generate certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain)
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=valid_days)
    ).add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_length), critical=True
    )

    if not is_ca:
        # Add key usage for end-entity certificates
        cert = cert.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]), critical=False
        )
    
    cert = cert.sign(issuer_key, hashes.SHA256())
    
    # Serialize to PEM format
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return cert_pem.decode(), key_pem.decode()

def generate_root_certificate(domain: str, org_name: str):
    """Generate a self-signed root certificate"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain)
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=3), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return cert_pem.decode(), key_pem.decode()

def generate_eth_key_pair():
    """
    Generate an Ethereum-compatible ECDSA key pair using secp256k1 curve.
    
    Returns:
        tuple: A tuple containing (private_key_hex, public_key_hex, eth_address)
        - private_key_hex: 32-byte private key in hex format (without '0x' prefix)
        - public_key_hex: 65-byte uncompressed public key in hex format (without '0x' prefix)
        - eth_address: 20-byte Ethereum address in hex format (with '0x' prefix)
    """
    # Generate private key using secp256k1 curve
    private_key = ec.generate_private_key(ec.SECP256K1())
    
    # Get public key in uncompressed format
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    # Format public key as uncompressed point (0x04 || x || y)
    x_bytes = public_numbers.x.to_bytes(32, 'big')
    y_bytes = public_numbers.y.to_bytes(32, 'big')
    public_key_bytes = b'\x04' + x_bytes + y_bytes
    
    # Get private key bytes
    private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
    
    # Generate Ethereum address (keccak256(public_key)[12:32])
    # Remove first byte (0x04) from public key before hashing
    h = hashlib.new('sha3_256')
    h.update(public_key_bytes[1:])
    eth_address = h.hexdigest()[-40:]  # Take last 20 bytes
    
    return (
        private_bytes.hex(),      # 32 bytes hex
        public_key_bytes.hex(),   # 65 bytes hex
        f"0x{eth_address}"        # 20 bytes hex with 0x prefix
    )

def generate_all_keys(domain: str, org_name: str) -> str:
    """
    Generate all required certificates and keys for the KMS system.
    
    Args:
        domain (str): Base domain name for certificates
        org_name (str): Organization name for certificates
        
    Returns:
        str: JSON string containing all generated keys and certificates
    """
    # Generate root CA
    root_ca_cert, root_ca_key = generate_root_certificate(f"root.{domain}", org_name)
    root_ca = x509.load_pem_x509_certificate(root_ca_cert.encode())
    root_key = serialization.load_pem_private_key(root_ca_key.encode(), password=None)
    
    # Generate temporary CA for clients (signed by root CA)
    temp_ca_cert, temp_ca_key = generate_signed_cert(
        domain=f"temp.{domain}",
        org_name=org_name,
        issuer_cert=root_ca,
        issuer_key=root_key,
        is_ca=True,
        path_length=1,  # Can only sign end-entity certs
        valid_days=30   # Short-lived
    )
    
    # Generate KMS RPC certificate (signed by root CA)
    kms_cert, kms_key = generate_signed_cert(
        domain=f"kms.{domain}",
        org_name=org_name,
        issuer_cert=root_ca,
        issuer_key=root_key,
        is_ca=False,    # End-entity certificate
        valid_days=365
    )
    
    # Generate Ethereum keys
    eth_sk, eth_pk, eth_addr = generate_eth_key_pair()
    
    # Prepare result
    result = {
        "root_ca_cert": root_ca_cert,
        "root_ca_key": root_ca_key,
        "temp_ca_cert": temp_ca_cert,
        "temp_ca_key": temp_ca_key,
        "kms_rpc_cert": kms_cert,
        "kms_rpc_key": kms_key,
        "eth_sk": eth_sk,
        "eth_pk": eth_pk,
        "eth_addr": eth_addr
    }
    
    return json.dumps(result, indent=2)
