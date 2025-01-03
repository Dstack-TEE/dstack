import unittest
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile
import json
import os
import sys

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import KMSManager, KMSState

class TestKMSManager(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.keys_path = Path(self.temp_dir) / "keys.json"
        self.kms_service = Mock()
        self.http_client = Mock()
        
        # Initialize KMS manager
        self.manager = KMSManager(
            keys_path=self.keys_path,
            kms_service=self.kms_service,
            http_client=self.http_client
        )
    
    def tearDown(self):
        # Clean up temporary files
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_initial_state_without_keys(self):
        """Test initial state when no keys exist"""
        state = self.manager.check_state()
        self.assertEqual(state, KMSState.NEEDS_SETUP)
        self.assertFalse(self.kms_service.start.called)
    
    def test_initial_state_with_keys(self):
        """Test initial state when keys exist"""
        # Create mock keys file
        mock_keys = {
            "root_ca_cert": "mock_cert",
            "root_ca_key": "mock_key"
        }
        with open(self.keys_path, 'w') as f:
            json.dump(mock_keys, f)
        
        state = self.manager.check_state()
        self.assertEqual(state, KMSState.READY)
    
    def test_bootstrap(self):
        """Test bootstrapping a new KMS instance"""
        domain = "test.example.com"
        org_name = "Test Org"
        
        # Bootstrap should create keys and start service
        result = self.manager.bootstrap(domain, org_name)
        
        # Verify keys were saved
        self.assertTrue(self.keys_path.exists())
        
        # Verify service was started
        self.kms_service.start.assert_called_once()
        
        # Verify state changed
        self.assertEqual(self.manager.check_state(), KMSState.READY)
    
    def test_onboard(self):
        """Test onboarding from existing KMS"""
        domain = "test.example.com"
        org_name = "Test Org"
        source_url = "https://source-kms.example.com"
        
        # Mock the HTTP response
        mock_keys = {
            "root_ca_cert": "mock_cert",
            "root_ca_key": "mock_key"
        }
        self.http_client.post.return_value.json.return_value = mock_keys
        
        # Onboard from source
        result = self.manager.onboard(source_url, domain, org_name)
        
        # Verify HTTP request was made correctly
        self.http_client.post.assert_called_once_with(
            f"{source_url}/api/v1/onboard",
            json={"domain": domain, "org_name": org_name},
            timeout=30
        )
        
        # Verify keys were saved
        self.assertTrue(self.keys_path.exists())
        with open(self.keys_path) as f:
            saved_keys = json.load(f)
        self.assertEqual(saved_keys, mock_keys)
        
        # Verify service was started
        self.kms_service.start.assert_called_once()
        
        # Verify state changed
        self.assertEqual(self.manager.check_state(), KMSState.READY)
    
    def test_invalid_keys(self):
        """Test behavior with invalid keys file"""
        # Create invalid keys file
        with open(self.keys_path, 'w') as f:
            f.write("invalid json")
        
        state = self.manager.check_state()
        self.assertEqual(state, KMSState.NEEDS_SETUP)
    
    def test_onboard_failure(self):
        """Test onboarding failure handling"""
        self.http_client.post.side_effect = Exception("Connection failed")
        
        with self.assertRaises(Exception):
            self.manager.onboard(
                "https://source-kms.example.com",
                "test.example.com",
                "Test Org"
            )
        
        # Verify no keys were saved
        self.assertFalse(self.keys_path.exists())
        
        # Verify service was not started
        self.assertFalse(self.kms_service.start.called)
        
        # Verify state remains unchanged
        self.assertEqual(self.manager.check_state(), KMSState.NEEDS_SETUP)

if __name__ == '__main__':
    unittest.main()
