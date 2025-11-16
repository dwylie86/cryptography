import pytest
from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_ed, rsa_ed
from modules.password import check_strength, hash_password, verify_password


# ----------------------------------------------------------------------
# FIXTURES (Setup for file testing)
# ----------------------------------------------------------------------
@pytest.fixture
def create_test_file(tmp_path):
    """
    Fixture to create a file with given content in the temporary directory.
    """
    def _create_test_file(filename, content, binary=False):
        p = tmp_path / filename
        if binary:
            p.write_bytes(content)
        else:
            p.write_text(content, encoding='utf-8')
        return str(p)
    return _create_test_file


# ----------------------------------------------------------------------
# 1. HASH MODULE TESTS (using the file fixture)
# ----------------------------------------------------------------------
def test_hash_file_known_content(create_test_file):
    """
    Tests if hash_file produces a known SHA-256 hash for a specific input.
    The expected hash
    '916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9'
    is the hash of the string 'test data'.
    """
    file_path = create_test_file("test_hash.txt", "test data")
    expected_hash = (
        "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    )

    assert hash_file(file_path) == expected_hash


def test_hash_file_consistency(create_test_file):
    """
    Test that two files with the exact
    same content produce identical hashes.
    """
    content = "This content should hash the same."
    file1 = create_test_file("same1.txt", content)
    file2 = create_test_file("same2.txt", content)

    assert hash_file(file1) == hash_file(file2)


def test_hash_file_nonexistent(tmp_path):
    """
    Test how hash_file handles a nonexistent path.
    Since open() raises FileNotFoundError, we expect pytest to catch it.
    """
    with pytest.raises(FileNotFoundError):
        hash_file(str(tmp_path / "nonexistent.txt"))


def test_verify_integrity_intact(create_test_file):
    """
    Test verification for two files with identical content (intact).
    """
    content = "Data is identical."
    file1 = create_test_file("intact1.txt", content)
    file2 = create_test_file("intact2.txt", content)

    assert verify_integrity(file1, file2) == "File is intact. Not modified."


def test_verify_integrity_modified(create_test_file):
    """Test verification for two files with different content (modified)."""
    file1 = create_test_file("mod1.txt", "Original Data")
    file2 = create_test_file("mod2.txt", "Altered Data")

    assert "modified" in verify_integrity(file1, file2)


# ----------------------------------------------------------------------
# 2. ENCRYPTION MODULE TESTS
# ----------------------------------------------------------------------
def test_aes_encryption_decryption():
    """
    Test that AES encryption is perfectly reversible.
    """
    original_message = "A highly sensitive test message."
    key, ciphertext_hex, plaintext = aes_ed(original_message)

    # 1. Test reversibility:
    # The decrypted plaintext must match the original message.
    assert plaintext == original_message

    # 2. Test for key and ciphertext generation (output format)
    assert len(key) == 64
    assert len(ciphertext_hex) > 0


def test_rsa_encryption_decryption():
    """
    Test that RSA encryption is perfectly reversible.
    """
    original_message = "This is a secret asymmetric message."

    # Your rsa_ed function expects a string input and encodes it inside
    ciphertext_hex, plaintext = rsa_ed(original_message)

    # 1. Test reversibility:
    # The decrypted plaintext must match the original message.
    assert plaintext == original_message

    # 2. Test that the ciphertext is a non-empty string in hex format
    assert len(ciphertext_hex) > 0


# ----------------------------------------------------------------------
# 3. PASSWORD MODULE TESTS
# ----------------------------------------------------------------------
def test_check_strength_weak():
    """
    Test that a simple password results in a 'Weak' response.
    """
    result = check_strength("1234")
    assert "Weak Password (Score of 0)" in result
    assert "Warning" in result
    assert "Suggestions" in result


def test_check_strength_strong():
    """
    Test that a strong password results in
    'Strong' or 'Very Strong' response.
    """
    # This password usually scores 3 or 4 in zxcvbn
    result = check_strength("CorrectHorseBatteryStaple1!")
    assert (
        result.startswith("Strong Password")
        or result.startswith("Very Strong Password")
    )
    # Verify no suggestion/warning block for strong passwords
    assert "Warning" not in result
    assert "Suggestions" not in result


def test_hash_password_consistency():
    """
    Test that hashing a password results in a
    valid bcrypt hash format (b'$2b$').
    """
    test_password = "my_secure_password"
    hashed = hash_password(test_password)

    # bcrypt hashes are bytes and follow the '$2b$' or '$2a$' format
    assert isinstance(hashed, bytes)
    assert hashed.startswith(b'$2b$')


def test_verify_password_correct():
    """
    Test verification when the passwords match.
    """
    password = "MyTestPassword123"
    hashed = hash_password(password)

    result = verify_password(password, hashed)
    assert "GRANTED" in result


def test_verify_password_incorrect():
    """
    Test verification when the passwords do not match.
    """
    password = "MyTestPassword123"
    incorrect_attempt = "MyWrongPassword456"
    hashed = hash_password(password)

    result = verify_password(incorrect_attempt, hashed)
    assert "DENIED" in result
