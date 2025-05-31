# Keylogger Utility

**⚠️ Important Security and Privacy Warning ⚠️**

This keylogger software is intended for legitimate security monitoring purposes only, such as monitoring your own systems.

*   **Legal Compliance:** Users are solely responsible for complying with all applicable local, state, federal, and international laws and regulations regarding user consent, data privacy, and employee monitoring. Do NOT use this software in violation of any laws or for any malicious purposes.
*   **Data Sensitivity:** Keyloggers capture all keystrokes, which can include highly sensitive information such as passwords, credit card numbers, personal messages, and other private data. Handle collected data with extreme care and security.
*   **Ethical Use:** Misusing this software to spy on individuals without their explicit, informed consent is unethical and illegal in most jurisdictions.

---

## Overview

This utility logs keystrokes to a local file. It is designed with a focus on security, incorporating encryption for the logged data.

## Features

*   Keystroke logging
*   AES encryption for log files
*   Secure log file path and permissions

## Setup and Usage

### Prerequisites

*   Python 3.x
*   `pyxhook` library (for Linux/X11)
*   `cryptography` library

You can install the necessary Python libraries using pip:
```bash
pip install pyxhook cryptography
```

### Configuration

1.  **Set the Encryption Password:**
    Logs are encrypted using AES. You **MUST** set an encryption password via the `KEYLOGGER_PASSWORD` environment variable. The keylogger will not start and will output an error if this variable is not set.

    Example (Linux/macOS):
    ```bash
    export KEYLOGGER_PASSWORD='your_very_strong_and_secret_password'
    ```
    Example (Windows - Command Prompt):
    ```bash
    set KEYLOGGER_PASSWORD=your_very_strong_and_secret_password
    ```
    **Important:**
    *   Choose a strong, unique password.
    *   Keep this password secret. If you lose the password, you will not be able to decrypt your logs.
    *   This password is used to derive the encryption key.

2.  **Running the Keylogger:**
    Once the environment variable is set, you can run the script:
    ```bash
    python Keylogger.py
    ```

### Log File Management

*   **Log File Location:** Encrypted log files are stored at `~/.local/share/keylogger/file.log`.
*   **Permissions:** The log directory (`~/.local/share/keylogger/`) is created with permissions `0o700` (owner access only), and the log file itself (`file.log`) is set to `0o600` (owner read/write only).
*   **Log Review and Deletion:** Regularly review your logs and securely delete them when they are no longer needed. Due to the sensitivity of the data, it's crucial to manage these files responsibly.
*   **Decryption:** A separate utility or function (not yet included in this script) would be required to decrypt and view the logs. This utility would need the same `KEYLOGGER_PASSWORD` that was used during logging.

## Disclaimer

This software is provided "AS-IS" without any warranties of any kind, express or implied. The developers and contributors are not responsible for any misuse, damage, or illegal activities conducted with this tool. Users are solely responsible for their actions and for complying with all applicable laws. By using this software, you agree to take full responsibility for its use.

---

*This README provides essential information for the responsible use of this keylogger utility.*
