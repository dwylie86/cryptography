from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_ed, rsa_ed
from modules.password import check_strength, hash_password, verify_password
from getpass import getpass


def menu():
    print(
        "Select operation:\n"
        "1. Hash file\n"
        "2. Check file integrity\n"
        "3. AES Encrypt/Decrypt\n"
        "4. RSA Encrypt/Decrypt\n"
        "5. Password Manager\n"
        "0. Exit"
    )


def toolkit():
    print("Welcome to the Cryptography Toolkit!\n")
    menu()
    while True:
        choice = input("\nEnter choice 0-5: ")

        match choice:
            case "1":
                file_path = input("Please enter file path: ")
                print(
                    f"SHA Hash of original file is:\n"
                    f"{hash_file(file_path)}"
                    )
            case "2":
                file_path1 = input("Please enter file path 1: ")
                file_path2 = input("Please enter file path 2: ")
                print(verify_integrity(file_path1, file_path2))
            case "3":
                message = input("Enter Message: ")
                key, ciphertext, plaintext = aes_ed(message)
                print(
                    f"AES Key: {key}\n"
                    f"AES Ciphertext: {ciphertext}\n"
                    f"AES Plaintext: {plaintext}"
                )
            case "4":
                message = input("Enter Message: ")
                ciphertext, plaintext = rsa_ed(message)
                print(
                    f"RSA message encrypted with a public key\n"
                    f"{ciphertext}\n"
                    f"RSA message decrypted with a private key\n"
                    f"{plaintext}"
                )
            case "5":
                while True:
                    password1 = getpass("Enter password to check strength: ")
                    print(check_strength(password1))
                    if check_strength(password1).startswith("Weak"):
                        print("Choose a stronger password.")
                    else:
                        break
                hashed_pw = hash_password(password1)
                print(f"Hashed password: {hashed_pw}")
                pw_attempt = getpass("Re-enter the password to verify: ")
                print(verify_password(pw_attempt, hashed_pw))
            case "0":
                break
            case _:
                print("Please enter a number (0-5)")
    print("Thank you for using the cryptography toolkit!")


if __name__ == "__main__":
    toolkit()
