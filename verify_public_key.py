"""
verify_public_key.py

This module provides functions to verify if a RSA public key's SHA-256 
fingerprint matches an expected value. It handles reading the public key from a PEM file, 
validates its format, and compares it with a provided fingerprint.

Helper functions are used to break down the process of fingerprint 
verification for better code modularity and readability.

Author: Narasimha Raghavan Veeraragavan
Date: 2024-10-03
Email: nara@kreftregisteret.no
Version: 1.0.0

Disclaimer:
    This software is provided "as is", without warranty of any kind, 
    express or implied, including but not limited to the warranties of merchantability, 
    fitness for a particular purpose, and noninfringement. In no event shall the authors 
    or copyright holders be liable for any claim, damages, or other liability, 
    whether in an action of contract, tort, or otherwise, arising from, 
    out of, or in connection with the software or the use or other dealings in the software.

"""

import hashlib
import os
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey

# Constants
MAX_FILE_SIZE = 5 * 1024  # 5 KB, adjust as necessary


def verify_public_key_fingerprint(public_key_file_path: str, expected_fingerprint: str):
    """
    Verifies if the provided SHA-256 fingerprint matches the public key's fingerprint from a file.

    This function validates the expected fingerprint, ensures the public key
    file is in a trusted directory, checks the file size, reads the PEM-formatted public key,
    loads the key, checks if the key is an RSA key and if the size is sufficient,
    and finally compares the computed fingerprint with the expected one.

    Args:
        public_key_file_path (str): The file path to the public key in PEM format.
        expected_fingerprint (str): The expected SHA-256 fingerprint in hex format.

    Returns:
        tuple: A tuple containing (boolean, exception_message).
               - boolean: True if the fingerprints match, False if not.
               - exception_message: None if success, otherwise the exception message.
    """
    try:
        # Fetch the trusted directory from environment variable
        trusted_directory = os.getenv("MICRODATA_TRUSTED_KEY_DIRECTORY")
        if trusted_directory is None:
            return (
                False,
                "Error: The environment variable TRUSTED_DIRECTORY is not set.",
            )

        # Step 1: Validate the expected fingerprint
        if not is_valid_fingerprint(expected_fingerprint):
            return False, "Invalid SHA-256 fingerprint provided."

        # Step 2: Validate the file path
        if not is_in_trusted_directory(public_key_file_path, trusted_directory):
            return (
                False,
                "Invalid file path. The file must be located in the trusted directory.",
            )

        # Step 3: Validate the file size
        if not is_valid_file_size(public_key_file_path):
            return False, "File is too large to process."

        # Step 4: Read and load the public key
        public_key_pem = read_public_key_file(public_key_file_path)
        public_key = load_public_key(public_key_pem)

        # Step 5: Validate the public key (RSA type and key size)
        if not is_valid_rsa_key(public_key):
            return False, "Expected an RSA public key."
        if not is_valid_key_size(public_key):
            return False, "Public key size is too small. Minimum is 2048 bits."

        # Step 6: Compare the fingerprints
        if not fingerprints_match(public_key, expected_fingerprint):
            return False, None

        return True, None

    # Handle specific exceptions
    except FileNotFoundError as e:
        return False, f"File not found: {e}"
    except PermissionError as e:
        return False, f"Permission denied: {e}"
    except IsADirectoryError as e:
        return False, f"Expected a file, but a directory was provided: {e}"
    except OSError as e:
        return False, f"OS error occurred: {e}"

    # Cryptography-related exceptions
    except UnsupportedAlgorithm as e:
        return False, f"Unsupported algorithm used in public key: {e}"
    except InvalidKey as e:
        return False, f"Invalid public key provided: {e}"

    # Value-related exceptions
    except ValueError as e:
        return False, f"Value error: {e}"
    except TypeError as e:
        return False, f"Type error: {e}"

    # Catch any unexpected exceptions as a last resort
    except Exception as e:  # pylint: disable=broad-except
        return False, f"An unexpected error occurred: {e}"


# Helper functions


def is_valid_fingerprint(fingerprint: str) -> bool:
    """
    Validates whether the provided fingerprint is a valid SHA-256 hash.

    Args:
        fingerprint (str): The fingerprint to validate.

    Returns:
        bool: True if the fingerprint is valid, False otherwise.
    """
    return len(fingerprint) == 64 and all(
        c in "0123456789abcdefABCDEF" for c in fingerprint
    )


def is_in_trusted_directory(file_path: str, trusted_directory: str) -> bool:
    """
    Validates whether the provided file path is located in the trusted directory.

    Args:
        file_path (str): The file path to validate.

    Returns:
        bool: True if the file path is in the trusted directory, False otherwise.
    """
    real_path = os.path.realpath(file_path)
    return os.path.commonpath([real_path, trusted_directory]) == trusted_directory


def is_valid_file_size(file_path: str) -> bool:
    """
    Validates whether the provided file size is within the allowed limit.

    Args:
        file_path (str): The file path to check.

    Returns:
        bool: True if the file size is valid, False otherwise.
    """
    return os.path.getsize(file_path) <= MAX_FILE_SIZE


def read_public_key_file(file_path: str) -> bytes:
    """
    Reads the public key from a PEM file.

    Args:
        file_path (str): The file path of the public key.

    Returns:
        bytes: The content of the public key file.
    """
    with open(file_path, "rb") as file:
        return file.read().strip()


def load_public_key(public_key_pem: bytes):
    """
    Loads a public key from its PEM format.

    Args:
        public_key_pem (bytes): The public key in PEM format.

    Returns:
        The public key object.
    """
    return load_pem_public_key(public_key_pem, backend=default_backend())


def is_valid_rsa_key(public_key) -> bool:
    """
    Checks if the provided public key is of RSA type.

    Args:
        public_key: The public key object to check.

    Returns:
        bool: True if the key is an RSA key, False otherwise.
    """
    return isinstance(public_key, rsa.RSAPublicKey)


def is_valid_key_size(public_key) -> bool:
    """
    Checks if the RSA public key meets the minimum key size requirement.

    Args:
        public_key: The RSA public key object.

    Returns:
        bool: True if the key size is valid, False otherwise.
    """
    return public_key.key_size >= 2048


def fingerprints_match(public_key: str, expected_fingerprint: str) -> bool:
    """
    Compares the SHA-256 fingerprint of the public key with the expected fingerprint.

    Args:
        public_key: The public key object.
        expected_fingerprint (str): The expected fingerprint to compare against.

    Returns:
        bool: True if the fingerprints match, False otherwise.
    """
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    computed_fingerprint = hashlib.sha256(public_key_der).hexdigest()
    print("Computed Fingerprint: ", computed_fingerprint)
    print("Provided Fingerprint: ", expected_fingerprint)
    return computed_fingerprint.lower() == expected_fingerprint.lower()


def main():
    """
    Main function to test the verify_public_key_fingerprint functionality.

    This function demonstrates an example usage of the `verify_public_key_fingerprint` function.
    Replace the file path and expected fingerprint with actual values for testing.
    """
    # Fetch the public key file path from the environment variable
    public_key_file_path = os.getenv("MICRODATA_SSB_PUBLIC_KEY_PATH")
    if public_key_file_path is None:
        print("Error: The environment variable PUBLIC_KEY_PATH is not set.")
        return

    # Fetch the provided fingerprint from the environment variable
    provided_fingerprint = os.getenv("EXPECTED_FINGERPRINT")
    if provided_fingerprint is None:
        print("Error: The environment variable EXPECTED_FINGERPRINT is not set.")
        return

    result, error_message = verify_public_key_fingerprint(
        public_key_file_path, provided_fingerprint
    )

    if result:
        print("The fingerprints match!")
    else:
        print(f"The fingerprints do not match. Exceptions: {error_message}")


if __name__ == "__main__":
    main()
