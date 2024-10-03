# Public Key and Fingerprint Verification

This script verifies if an RSA public key's **SHA-256 fingerprint** matches the provided fingerprint. It checks the integrity of the RSA public key by comparing the computed fingerprint with the one received from a trusted partner.

## Requirements

Before running the script, ensure the following dependencies are installed in your Python environment. These can be installed via `requirements.txt` or directly using `pip`.

### Required Libraries:
- `cryptography`
- `hashlib`
- `os`

### Installing Dependencies:

1. **Create a Virtual Environment** (Optional, but recommended)

    You can create a virtual environment using the built-in `venv` module.

    - **On macOS/Linux**:
      ```bash
      python3 -m venv venv
      ```
    - **On Windows**:
      ```bash
      python -m venv venv
      ```

2. **Activate the Virtual Environment**

    - **On macOS/Linux**:
      ```bash
      source venv/bin/activate
      ```
    - **On Windows**:
      ```bash
      venv\Scripts\activate
      ```

3. **Install Dependencies**:

    After activating the virtual environment, run:

    ```bash
    pip install -r requirements.txt
    ```

---

## Environment Setup

The script uses environment variables to specify paths and expected values. Follow these steps to set the required environment variables.

### Step 1: Set Environment Variables

- **`MICRODATA_SSB_PUBLIC_KEY_PATH`**: The path to the RSA public key in PEM format.
- **`MICRODATA_TRUSTED_KEY_DIRECTORY`**: The directory where the trusted public keys are stored.
- **`EXPECTED_FINGERPRINT`**: The expected SHA-256 fingerprint of the RSA public key.

### Step 2: How to Set Environment Variables

#### On macOS/Linux:

To set the environment variables in your terminal, use the following commands:

```bash
export MICRODATA_SSB_PUBLIC_KEY_PATH="/path/to/trusted/directory/public_key.pem"
export MICRODATA_TRUSTED_KEY_DIRECTORY="/path/to/trusted/directory"
export EXPECTED_FINGERPRINT="your_expected_sha256_fingerprint"
```

#### On Windows (Command Prompt):
To set the environment variables, use the following commands:

```bash
set MICRODATA_SSB_PUBLIC_KEY_PATH="C:\path\to\trusted\directory\public_key.pem"
set MICRODATA_TRUSTED_KEY_DIRECTORY="C:\path\to\trusted\directory"
set EXPECTED_FINGERPRINT="your_expected_sha256_fingerprint"
```

#### On Windows (Power Shell):
Alternatively, if you're using PowerShell, use:

```bash
$env:MICRODATA_SSB_PUBLIC_KEY_PATH="C:\path\to\trusted\directory\public_key.pem"
$env:MICRODATA_TRUSTED_KEY_DIRECTORY="C:\path\to\trusted\directory"
$env:EXPECTED_FINGERPRINT="your_expected_sha256_fingerprint"
```

---
## Run the Script
Once you have set the environment variables and installed the required dependencies, you can run the script by executing:

```bash
python verify_public_key.py
```
---
## Example Output
When the fingerprints match, it means that the integrity of the RSA public key is intact and verified. In this case, an output looks like the following: 
```bash
Computed Fingerprint:  5d41402abc4b2a76b9719d911017c592
Provided Fingerprint:  5d41402abc4b2a76b9719d911017c592
The fingerprints match!
```
If the fingerprints don't match, it signals potential tampering or corruption, meaning something is wrong in the process of verification. Exceptions are usually thrown if there are any. 
In the case where there is no exeception but the fingerprint mismatches, an output looks like the following:
```bash
Computed Fingerprint:  5d41402abc4b2a76b9719d911017c592
Provided Fingerprint:  abvederabc4b2a76b9719d911017c998
The fingerprints do not match. Exceptions: None
```
