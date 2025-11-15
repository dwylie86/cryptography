import hashlib

original = (
    "/home/ubuntuserver/personal/"
    "cryptography/sample_files/frankenstein.txt"
)
good_copy = (
    "/home/ubuntuserver/personal/"
    "cryptography/sample_files/frankenstein_good.txt"
)
bad_copy = (
    "/home/ubuntuserver/personal/"
    "cryptography/sample_files/frankenstein_bad.txt"
)


def hash_file(file_path):
    h = hashlib.new("sha256")
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024)
            if chunk == b"":
                break
            h.update(chunk)
    return h.hexdigest()


def verify_integrity(file1, file2):
    hash1 = hash_file(file1)
    hash2 = hash_file(file2)
    print(f"Checking Integrity between {file1} and {file2}")
    if hash1 == hash2:
        return "File is intact. Not modified."
    return "File has been modified or is differnt"


if __name__ == "__main__":
    hashed_file = hash_file(original)
    print(
        f"SHA Hash of original file is:\n"
        f"{hashed_file}"
    )
    print(
        f"verifying integrity: Original and Good Copy:\n"
        f"{verify_integrity(original, good_copy)}\n"
        f"verifying integrity: Original and Bad Copy:\n"
        f"{verify_integrity(original, bad_copy)}\n"
    )
