# **🔐 Python Command-Line Cryptography Toolkit**

This repository contains a fully functional command-line interface (CLI) application built with Python to demonstrate and apply fundamental cryptographic concepts. Inspired by the freeCodeCamp [Cryptography for Beginners](https://www.youtube.com/watch?v=kb_scuDUHls) tutorial on YouTube, this project provides a hands-on toolkit for securing data, checking file integrity, and managing user passwords.

The toolkit is designed to be beginner-friendly while implementing industry-standard algorithms like SHA-256, AES, and RSA.

## **🛠️ Installation and Setup**

### **Prerequisites**

You must have **Python 3.x** installed on your system. It is highly recommended to use a virtual environment for dependency management.

Install dependencies:  
   The project relies on several external Python libraries for complex cryptographic primitives and strength checking.  
   pip install cryptography zxcvbn bcrypt

   *(Note: hashlib and getpass are typically included in the standard Python library.)*

## **📚 Core Libraries Used**

* **hashlib**: Standard library used for common hashing algorithms (SHA-256).  
* **cryptography**: The primary library for implementing AES and RSA encryption.  
* **zxcvbn**: Used in the password manager for accurate, robust password strength estimation.  
* **bcrypt**: Used for secure password hashing and verification in the password manager.