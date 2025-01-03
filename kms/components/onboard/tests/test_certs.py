import unittest
import os
import sys
import json
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cert_generator import (
    generate_root_certificate,
    generate_signed_cert,
    generate_eth_key_pair,
    generate_all_keys
)

class TestCertificateGeneration(unittest.TestCase):
    def setUp(self):
        # Common test inputs
        self.domain = "test.example.com"
        self.org_name = "Test Organization"
        self.cert_pem, self.key_pem = generate_root_certificate(self.domain, self.org_name)
        self.cert = x509.load_pem_x509_certificate(self.cert_pem.encode())
        self.private_key = serialization.load_pem_private_key(
            self.key_pem.encode(),
            password=None
        )
        
    def test_certificate_format(self):
        """Test basic certificate format and encoding"""
        # Verify certificate format
        self.assertIsInstance(self.cert, x509.Certificate)
        self.assertIsInstance(self.private_key, ec.EllipticCurvePrivateKey)
        
        # Verify key curve
        self.assertEqual(self.private_key.curve.name, "secp256r1")
    
    def test_certificate_attributes(self):
        """Test certificate subject and issuer attributes"""
        # Check subject attributes
        subject = self.cert.subject
        self.assertEqual(subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, self.domain)
        self.assertEqual(subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, self.org_name)
        self.assertEqual(subject.get_attributes_for_oid(NameOID.DOMAIN_COMPONENT)[0].value, self.domain)
        
        # Verify self-signed (issuer should match subject)
        self.assertEqual(self.cert.subject, self.cert.issuer)
    
    def test_certificate_validity(self):
        """Test certificate validity period"""
        now = datetime.now()
        
        # Check validity period
        not_valid_before = self.cert.not_valid_before_utc.replace(tzinfo=None)
        not_valid_after = self.cert.not_valid_after_utc.replace(tzinfo=None)
        
        self.assertLess(not_valid_before, now)
        self.assertGreater(not_valid_after, now + timedelta(days=364))
    
    def test_certificate_extensions(self):
        """Test certificate extensions"""
        # Check basic constraints
        basic_constraints = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(basic_constraints.value.ca)
        self.assertEqual(basic_constraints.value.path_length, 3)
        
        # Check key usage
        key_usage = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        )
        self.assertTrue(key_usage.value.key_cert_sign)
        self.assertTrue(key_usage.value.crl_sign)
    
    def test_key_properties(self):
        """Test private key properties and compatibility"""
        # Get public key from private key
        public_key = self.private_key.public_key()
        
        # Verify that the certificate's public key matches
        self.assertEqual(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            self.cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    def test_key_usage(self):
        """Test key pair functionality"""
        # Sign some data
        data = b"test data"
        signature = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Verify with public key
        public_key = self.cert.public_key()
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            self.fail(f"Signature verification failed: {str(e)}")
    
    def test_signature_verification(self):
        """Test certificate signature verification"""
        try:
            # Verify certificate signature
            public_key = self.cert.public_key()
            public_key.verify(
                self.cert.signature,
                self.cert.tbs_certificate_bytes,
                ec.ECDSA(self.cert.signature_hash_algorithm)
            )
        except Exception as e:
            self.fail(f"Certificate signature verification failed: {str(e)}")

class TestEthereumKeyGeneration(unittest.TestCase):
    def test_eth_key_format(self):
        """Test Ethereum key pair format and lengths"""
        priv_key_hex, pub_key_hex, eth_addr = generate_eth_key_pair()
        
        # Check private key format (32 bytes = 64 hex chars)
        self.assertEqual(len(priv_key_hex), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in priv_key_hex))
        
        # Check public key format (65 bytes = 130 hex chars)
        self.assertEqual(len(pub_key_hex), 130)
        self.assertTrue(all(c in '0123456789abcdef' for c in pub_key_hex))
        self.assertEqual(pub_key_hex[:2], '04')  # Uncompressed public key marker
        
        # Check Ethereum address format (20 bytes = 40 hex chars + '0x' prefix)
        self.assertEqual(len(eth_addr), 42)
        self.assertTrue(eth_addr.startswith('0x'))
        self.assertTrue(all(c in '0123456789abcdef' for c in eth_addr[2:]))

    def test_eth_key_derivation(self):
        """Test that public key and address are correctly derived from private key"""
        priv_key_hex, pub_key_hex, eth_addr = generate_eth_key_pair()
        
        # Recreate key pair from private key bytes
        priv_value = int.from_bytes(bytes.fromhex(priv_key_hex), 'big')
        private_key = ec.derive_private_key(priv_value, ec.SECP256K1())
        public_key = private_key.public_key()
        
        # Format public key in uncompressed format
        numbers = public_key.public_numbers()
        x_bytes = numbers.x.to_bytes(32, 'big')
        y_bytes = numbers.y.to_bytes(32, 'big')
        derived_pub_key = (b'\x04' + x_bytes + y_bytes).hex()
        
        # Verify public key matches
        self.assertEqual(pub_key_hex, derived_pub_key)
        
        # Verify address is correctly derived from public key
        h = hashlib.new('sha3_256')
        h.update(bytes.fromhex(pub_key_hex)[1:])  # Skip '04' prefix
        expected_addr = f"0x{h.hexdigest()[-40:]}"
        self.assertEqual(eth_addr.lower(), expected_addr.lower())

    def test_eth_key_uniqueness(self):
        """Test that generated keys are unique"""
        keys = [generate_eth_key_pair() for _ in range(3)]
        
        # Check all private keys are different
        priv_keys = [k[0] for k in keys]
        self.assertEqual(len(set(priv_keys)), len(priv_keys))
        
        # Check all public keys are different
        pub_keys = [k[1] for k in keys]
        self.assertEqual(len(set(pub_keys)), len(pub_keys))
        
        # Check all addresses are different
        addresses = [k[2] for k in keys]
        self.assertEqual(len(set(addresses)), len(addresses))

    def test_eth_key_signing(self):
        """Test that the generated keys can sign and verify messages"""
        priv_key_hex, _, _ = generate_eth_key_pair()
        
        # Create private key object
        priv_value = int.from_bytes(bytes.fromhex(priv_key_hex), 'big')
        private_key = ec.derive_private_key(priv_value, ec.SECP256K1())
        public_key = private_key.public_key()
        
        # Test signing and verification
        message = b"test message"
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            self.fail(f"Signature verification failed: {str(e)}")

    def test_eth_address_derivation_steps(self):
        """Test Ethereum address derivation process step by step"""
        # Get a key pair
        priv_key_hex, pub_key_hex, eth_addr = generate_eth_key_pair()
        
        # Step 1: Start with the full public key (65 bytes)
        self.assertEqual(len(pub_key_hex), 130)  # 65 bytes in hex = 130 chars
        self.assertTrue(pub_key_hex.startswith('04'))  # Uncompressed public key marker
        
        # Step 2: Remove the '04' prefix
        pub_key_for_hash = pub_key_hex[2:]  # Remove '04' prefix
        self.assertEqual(len(pub_key_for_hash), 128)  # Should be 64 bytes (128 chars)
        
        # Step 3: Calculate Keccak-256 hash
        h = hashlib.new('sha3_256')
        h.update(bytes.fromhex(pub_key_for_hash))
        full_hash = h.hexdigest()
        self.assertEqual(len(full_hash), 64)  # Keccak-256 produces 32 bytes (64 chars)
        
        # Step 4: Take last 20 bytes (40 chars) of the hash
        address_bytes = full_hash[-40:]
        self.assertEqual(len(address_bytes), 40)
        
        # Step 5: Add '0x' prefix
        calculated_addr = f"0x{address_bytes}"
        self.assertEqual(len(calculated_addr), 42)
        
        # Verify the calculated address matches the one returned by the function
        self.assertEqual(calculated_addr.lower(), eth_addr.lower())
        
        # Additional verification: address is valid hex
        self.assertTrue(all(c in '0123456789abcdef' for c in address_bytes.lower()))

class TestComprehensiveKeyGeneration(unittest.TestCase):
    def setUp(self):
        self.domain = "test.example.com"
        self.org_name = "Test Organization"
        self.result = json.loads(generate_all_keys(self.domain, self.org_name))
    
    def test_result_structure(self):
        """Test that all required keys are present in the result"""
        expected_keys = {
            "root_ca_cert", "root_ca_key", 
            "temp_ca_cert", "temp_ca_key",
            "kms_rpc_cert", "kms_rpc_key",
            "eth_sk", "eth_pk", "eth_addr"
        }
        self.assertEqual(set(self.result.keys()), expected_keys)
    
    def test_certificate_chain(self):
        """Test certificate chain validity"""
        # Load certificates
        root_ca = x509.load_pem_x509_certificate(self.result["root_ca_cert"].encode())
        temp_ca = x509.load_pem_x509_certificate(self.result["temp_ca_cert"].encode())
        kms_cert = x509.load_pem_x509_certificate(self.result["kms_rpc_cert"].encode())
        
        # Verify temp CA is signed by root CA
        root_ca_pub_key = root_ca.public_key()
        try:
            root_ca_pub_key.verify(
                temp_ca.signature,
                temp_ca.tbs_certificate_bytes,
                ec.ECDSA(temp_ca.signature_hash_algorithm)
            )
        except Exception as e:
            self.fail(f"Temp CA verification failed: {str(e)}")
        
        # Verify KMS cert is signed by root CA
        try:
            root_ca_pub_key.verify(
                kms_cert.signature,
                kms_cert.tbs_certificate_bytes,
                ec.ECDSA(kms_cert.signature_hash_algorithm)
            )
        except Exception as e:
            self.fail(f"KMS cert verification failed: {str(e)}")
    
    def test_certificate_properties(self):
        """Test specific properties of each certificate"""
        # Load certificates
        root_ca = x509.load_pem_x509_certificate(self.result["root_ca_cert"].encode())
        temp_ca = x509.load_pem_x509_certificate(self.result["temp_ca_cert"].encode())
        kms_cert = x509.load_pem_x509_certificate(self.result["kms_rpc_cert"].encode())
        
        # Check root CA properties
        root_constraints = root_ca.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(root_constraints.value.ca)
        self.assertEqual(root_constraints.value.path_length, 3)
        
        # Check temp CA properties
        temp_constraints = temp_ca.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(temp_constraints.value.ca)
        self.assertEqual(temp_constraints.value.path_length, 1)
        
        # Check KMS cert properties
        kms_constraints = kms_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertFalse(kms_constraints.value.ca)
        
        # Check KMS cert key usage
        key_usage = kms_cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        )
        self.assertTrue(key_usage.value.digital_signature)
        self.assertTrue(key_usage.value.key_encipherment)
        
        ext_key_usage = kms_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, ext_key_usage.value)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, ext_key_usage.value)
    
    def test_certificate_validity(self):
        """Test certificate validity periods"""
        # Load certificates
        root_ca = x509.load_pem_x509_certificate(self.result["root_ca_cert"].encode())
        temp_ca = x509.load_pem_x509_certificate(self.result["temp_ca_cert"].encode())
        kms_cert = x509.load_pem_x509_certificate(self.result["kms_rpc_cert"].encode())
        
        now = datetime.now()
        
        # Check root CA validity (1 year)
        root_validity = root_ca.not_valid_after_utc - root_ca.not_valid_before_utc
        self.assertGreater(root_validity.days, 364)
        self.assertLess(root_validity.days, 366)
        
        # Check temp CA validity (30 days)
        temp_validity = temp_ca.not_valid_after_utc - temp_ca.not_valid_before_utc
        self.assertGreater(temp_validity.days, 29)
        self.assertLess(temp_validity.days, 31)
        
        # Check KMS cert validity (1 year)
        kms_validity = kms_cert.not_valid_after_utc - kms_cert.not_valid_before_utc
        self.assertGreater(kms_validity.days, 364)
        self.assertLess(kms_validity.days, 366)
    
    def test_eth_key_consistency(self):
        """Test that Ethereum keys are valid and consistent"""
        # Verify Ethereum key formats
        self.assertEqual(len(self.result["eth_sk"]), 64)  # 32 bytes hex
        self.assertEqual(len(self.result["eth_pk"]), 130)  # 65 bytes hex
        self.assertEqual(len(self.result["eth_addr"]), 42)  # 20 bytes hex with 0x prefix
        
        # Verify address derivation
        h = hashlib.new('sha3_256')
        h.update(bytes.fromhex(self.result["eth_pk"][2:]))  # Skip '04' prefix
        expected_addr = f"0x{h.hexdigest()[-40:]}"
        self.assertEqual(self.result["eth_addr"].lower(), expected_addr.lower())

if __name__ == '__main__':
    unittest.main()