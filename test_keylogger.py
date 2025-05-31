import unittest
import os
import subprocess
import tempfile
import sys
import base64 # Needed for fallback get_cipher_suite if imports fail
import hashlib # Needed for fallback get_cipher_suite if imports fail
from cryptography.fernet import Fernet

# Direct imports from Keylogger.py
# If Keylogger.py is structured correctly (e.g., pyxhook imported conditionally),
# these imports should work without issue when testing non-logging parts.
from Keylogger import generate_fernet_key, get_cipher_suite, SALT, DEFAULT_LOG_FILE

class TestEncryptionDecryption(unittest.TestCase):
    def setUp(self):
        self.test_password = "test_password_123_abc"
        # This env var is primarily for subprocess calls. Direct calls use self.test_password.
        os.environ['KEYLOGGER_PASSWORD_FOR_TEST'] = self.test_password

        try:
            self.cipher = get_cipher_suite(self.test_password, SALT)
        except Exception as e:
            self.fail(f"setUp failed to create cipher: {e}")

        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_log_file = os.path.join(self.temp_dir.name, "test_encrypted.log")
        self.keylogger_script_path = os.path.join(os.path.dirname(__file__), 'Keylogger.py')
        # Simple fallback if __file__ is not defined (e.g. interactive session)
        if not os.path.exists(self.keylogger_script_path):
             self.keylogger_script_path = "Keylogger.py"


    def tearDown(self):
        self.temp_dir.cleanup()
        if 'KEYLOGGER_PASSWORD_FOR_TEST' in os.environ:
            del os.environ['KEYLOGGER_PASSWORD_FOR_TEST']

    def test_encrypt_decrypt_cycle(self):
        """Test direct encryption and decryption of a sample string."""
        original_string = "This is a secret message for testing! With symbols: !@#$%"
        encrypted_data = self.cipher.encrypt(original_string.encode('utf-8'))
        decrypted_data = self.cipher.decrypt(encrypted_data)
        self.assertEqual(decrypted_data.decode('utf-8'), original_string)

    def test_decryption_utility_valid(self):
        """Test the --decrypt mode with a valid encrypted file."""
        original_lines = [
            "First line: Hello World!",
            "Second line: 1234567890",
            "Third line: Special characters like !@#$%^&*()_+[]{};':\",./<>?`~"
        ]

        with open(self.test_log_file, 'wb') as f:
            for line in original_lines:
                encrypted_line = self.cipher.encrypt(line.encode('utf-8'))
                f.write(encrypted_line + b'\n')

        process_env = os.environ.copy()
        process_env['KEYLOGGER_PASSWORD'] = self.test_password # Keylogger.py expects KEYLOGGER_PASSWORD

        result = subprocess.run(
            [sys.executable, self.keylogger_script_path, '--decrypt', self.test_log_file],
            capture_output=True,
            text=True,
            env=process_env
        )

        self.assertEqual(result.returncode, 0, f"Decryption script failed. Stderr:\n{result.stderr}\nStdout:\n{result.stdout}")

        output_lines = result.stdout.strip().split('\n')
        # Filter out potential info messages from Keylogger.py if any are printed before actual output
        output_lines = [line for line in output_lines if not line.startswith("Attempting to decrypt")]

        self.assertEqual(len(output_lines), len(original_lines),
                         f"Number of decrypted lines does not match original. Got:\n{result.stdout}\nExpected {len(original_lines)} lines.")
        for i, expected_line in enumerate(original_lines):
            self.assertEqual(output_lines[i], expected_line, f"Decrypted line {i+1} does not match.")

    def test_decryption_utility_invalid_password(self):
        """Test the --decrypt mode with an invalid password."""
        original_line = "This data should not be readable."
        # Encrypt with the correct password
        with open(self.test_log_file, 'wb') as f:
            encrypted_line = self.cipher.encrypt(original_line.encode('utf-8'))
            f.write(encrypted_line + b'\n')

        wrong_password = "this_is_not_the_password"
        process_env = os.environ.copy()
        process_env['KEYLOGGER_PASSWORD'] = wrong_password # Use wrong password for decryption

        result = subprocess.run(
            [sys.executable, self.keylogger_script_path, '--decrypt', self.test_log_file],
            capture_output=True,
            text=True,
            env=process_env
        )

        # Keylogger.py's decrypt_log_file prints to stderr for failed lines.
        self.assertIn("Error decrypting line", result.stderr, "Expected error message for decryption failure not found in stderr.")
        # Stdout should be empty, or only contain the "Attempting to decrypt..." message
        # if we consider that part of the output.
        # For robustness, check that the original_line is not in stdout.
        self.assertNotIn(original_line, result.stdout, "Original content unexpectedly found in stdout despite wrong password.")

        # Depending on how Keylogger.py handles this, stdout might contain the "Attempting to decrypt..." message.
        # If the only output is that message, then .strip() might be empty or just that.
        # A more robust check is that no *decrypted content* appears.
        # If the script exits with 1 on any decrypt error, check result.returncode != 0
        # Current Keylogger.py does not exit(1) on per-line decrypt error.

class TestSetupAndConfiguration(unittest.TestCase):
    def setUp(self):
        self.keylogger_script_path = os.path.join(os.path.dirname(__file__), 'Keylogger.py')
        if not os.path.exists(self.keylogger_script_path): # Basic fallback
             self.keylogger_script_path = "Keylogger.py"

        self.original_password_env = os.environ.pop('KEYLOGGER_PASSWORD', None)

    def tearDown(self):
        if self.original_password_env is not None:
            os.environ['KEYLOGGER_PASSWORD'] = self.original_password_env

    def test_missing_password_error(self):
        """Test script exits with error if KEYLOGGER_PASSWORD is not set."""
        # Ensure KEYLOGGER_PASSWORD is not in the environment for this test
        current_env = os.environ.copy()
        if 'KEYLOGGER_PASSWORD' in current_env:
            del current_env['KEYLOGGER_PASSWORD']

        # Test attempt to run in logging mode (no args)
        result_log_mode = subprocess.run(
            [sys.executable, self.keylogger_script_path],
            capture_output=True,
            text=True,
            env=current_env # Pass the environment without the password
        )
        self.assertNotEqual(result_log_mode.returncode, 0, "Script should exit non-zero if password missing (logging mode).")
        self.assertIn("KEYLOGGER_PASSWORD environment variable not set", result_log_mode.stderr)

        # Test attempt to run in decryption mode
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            dummy_file_path = tmpfile.name
        try:
            result_decrypt_mode = subprocess.run(
                [sys.executable, self.keylogger_script_path, '--decrypt', dummy_file_path],
                capture_output=True,
                text=True,
                env=current_env # Pass the environment without the password
            )
            self.assertNotEqual(result_decrypt_mode.returncode, 0, "Script should exit non-zero if password missing (decryption mode).")
            self.assertIn("KEYLOGGER_PASSWORD environment variable not set", result_decrypt_mode.stderr)
        finally:
            os.remove(dummy_file_path)

if __name__ == '__main__':
    unittest.main()
