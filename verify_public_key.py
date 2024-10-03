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
Version: 1.1.0

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
import subprocess
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
        error_message = None

        # Step 1: Fetch the trusted directory from environment variable
        trusted_directory = os.getenv("MICRODATA_TRUSTED_KEY_DIRECTORY")
        if not trusted_directory:
            error_message = (
                "Error: The environment variable TRUSTED_DIRECTORY is not set."
            )

        # Step 2: Validate the expected fingerprint
        if not is_valid_fingerprint(expected_fingerprint):
            error_message = "Invalid SHA-256 fingerprint provided."

        # Step 3: Validate the file path
        if not is_in_trusted_directory(public_key_file_path, trusted_directory):
            error_message = (
                "Invalid file path. The file must be located in the trusted directory."
            )

        # Step 4: Validate the file size
        if not is_valid_file_size(public_key_file_path):
            error_message = "File is too large to process."

        # Step 5: Read and load the public key
        else:
            public_key_pem = read_public_key_file(public_key_file_path)
            public_key = load_public_key(public_key_pem)

            # Step 6: Validate the public key (RSA type and key size)
            if not is_valid_rsa_key(public_key):
                error_message = "Expected an RSA public key."
            if not is_valid_key_size(public_key):
                error_message = "Public key size is too small. Minimum is 2048 bits."

            # Step 7: Compare the fingerprints
            if not fingerprints_match(
                public_key, expected_fingerprint, public_key_file_path
            ):
                error_message = "Fingerprints do not match."

        if error_message:
            return False, error_message

        return True, None

    # Handle specific exceptions
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as e:
        return False, str(e)

    except (UnsupportedAlgorithm, InvalidKey) as e:
        return False, f"Cryptography error: {e}"

    except (ValueError, TypeError) as e:
        return False, f"Value or type error: {e}"

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


def sha256_fingerprint_with_openssl(public_key_pem_path: str) -> str:
    """Computes the SHA-256 fingerprint of a public key using OpenSSL."""
    try:
        result = subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                public_key_pem_path,
                "-pubout",
                "-outform",
                "DER",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,  # Ensure we catch errors
        )
        output = subprocess.run(
            ["openssl", "sha256"],
            input=result.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        # Decode and clean up the output, removing 'SHA2-256(stdin)='
        fingerprint = output.stdout.decode("utf-8").strip()
        fingerprint = fingerprint.split("=")[-1].strip()  # Extract the hash part only

        return fingerprint

    except subprocess.CalledProcessError as e:
        # Handle the error, possibly logging or returning an appropriate message
        print(f"Error running OpenSSL: {e}")
        return None


def fingerprints_match(
    public_key, expected_fingerprint: str, public_key_pem_path: str
) -> bool:
    """
    Compares the SHA-256 fingerprint of a public key with an expected
    fingerprint using multiple methods. This function attempts to match the fingerprint
    of a given public key with the expected fingerprint using three different methods:

    1. Computes the SHA-256 fingerprint using the DER-encoded format of the public key.
    2. Computes the SHA-256 fingerprint using the PEM-encoded format of the public key.
    3. If a PEM file path is provided, the function computes the SHA-256 fingerprint
       using the OpenSSL command-line tool.

    Args:
        public_key: The public key object (supports `public_bytes` method for serialization).
        expected_fingerprint (str): The expected SHA-256 fingerprint to compare against.
        public_key_pem_path (str): The file path to the PEM-encoded public key,
        used for the OpenSSL fingerprint computation.

    Returns:
        bool: True if any of the computed fingerprints (DER, PEM, or OpenSSL)
        match the expected fingerprint. False otherwise.

    Additional Information:
        - The fingerprints are compared in a case-insensitive manner.
        - If the `public_key_pem_path` is provided, the function uses OpenSSL
        to compute the fingerprint from the PEM file.
        - The function prints the computed fingerprints for debugging purposes,
        including the results from DER, PEM, and OpenSSL (if applicable).

    """
    # 1. Compute the fingerprint from the DER-encoded public key (cryptography library)

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    computed_fingerprint_der = hashlib.sha256(public_key_der).hexdigest()

    # 2. Compute the fingerprint from the PEM-encoded public key (direct PEM bytes)

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    computed_fingerprint_pem = hashlib.sha256(public_key_pem).hexdigest()

    # 3. Compute the fingerprint using OpenSSL (optional if PEM path is provided)

    if public_key_pem_path:
        computed_fingerprint_openssl = sha256_fingerprint_with_openssl(
            public_key_pem_path
        )
    else:
        computed_fingerprint_openssl = None

    print("Computed Fingerprint DER Encoded Bytes: ", computed_fingerprint_der)
    print("Computed Fingerprint PEM Encoded Bytes: ", computed_fingerprint_pem)
    if computed_fingerprint_openssl:
        print("Computed Fingerprint (OpenSSL): ", computed_fingerprint_openssl)
    print("Provided Fingerprint: ", expected_fingerprint)

    if computed_fingerprint_der.lower() == expected_fingerprint.lower():
        return True
    if computed_fingerprint_pem.lower() == expected_fingerprint.lower():
        return True
    if (
        computed_fingerprint_openssl
        and computed_fingerprint_openssl.lower() == expected_fingerprint.lower()
    ):
        return True
    return False


def main():
    """
    Main function to test the verify_public_key_fingerprint functionality.

    This function demonstrates how to verify the SHA-256 fingerprint of a public key against
    an expected fingerprint. It fetches the public key file path and the expected fingerprint
    from environment variables.

    Environment Variables:
        MICRODATA_SSB_PUBLIC_KEY_PATH: The file path to the PEM-encoded public key.
        EXPECTED_FINGERPRINT: The expected SHA-256 fingerprint of the public key.

    Functionality:
        - Fetches the public key file path from the "MICRODATA_SSB_PUBLIC_KEY_PATH"
        - Fetches the expected fingerprint from the "EXPECTED_FINGERPRINT"
        - Calls the `verify_public_key_fingerprint` function to compare the computed fingerprint
          of the public key against the provided expected fingerprint.
        - Prints a success message if the fingerprints match or an error message if they do not.

    Returns:
        None: The function prints the result of the fingerprint comparison.
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
