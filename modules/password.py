from zxcvbn import zxcvbn
from getpass import getpass
import bcrypt


def check_strength(password):
    result = zxcvbn(password)
    score = result["score"]
    if score == 3:
        response = "Strong Password (Score of 3)"
    elif score == 4:
        response = "Very Strong Password (Score of 4)"
    else:
        feedback = result.get("feedback")
        warning = feedback.get("warning")
        suggestions = feedback.get("suggestions")
        response = (
            f"Weak Password (Score of {score})\n"
            f"Warning: {warning}\n"
            f"Suggestions:\n- {'\n- '.join(suggestions)}"
        )
    return response


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed


def verify_password(pw_entered, hashed):
    if bcrypt.checkpw(pw_entered.encode(), hashed):
        return "Password is correct. Access is GRANTED!"
    else:
        return "Password is incorrect. Access is DENIED!"


if __name__ == "__main__":
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
