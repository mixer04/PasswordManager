# Password Manager

A simple password manager app written in Python using the `cryptography` library for encryption and decryption.

## Features

- Securely stores passwords using encryption.
- Generates strong, random passwords.
- Checks the strength of passwords based on various criteria.
- Saves and loads passwords from a JSON file.
- Allows searching for passwords by service name.

## Usage

1. Run the `password_manager.py` script.
2. Enter your master password when prompted.
3. Choose an option from the menu:
   - Add password: Enter the service name and password to add.
   - Get password: Enter the service name to retrieve the password.
   - Update password: Enter the service name and new password to update.
   - Delete password: Enter the service name to delete the password.
   - Generate password: Enter the desired password length to generate a random password.
   - Check password strength: Enter the password to check its strength.
   - Search password: Enter a search term to find passwords containing it in their service name.
   - Save and exit: Save the passwords and exit the app.

## Notes

- The master password is used to encrypt and decrypt the encryption key.
- The encryption key is derived from the master password using PBKDF2HMAC.
- The passwords are stored in a JSON file named `passwords.json`.
- The key and passwords are encrypted using the Fernet symmetric encryption algorithm.
- The generated passwords are random and contain a mix of uppercase letters, lowercase letters, digits, and special characters.
- The password strength is checked based on various criteria, such as length, presence of uppercase letters, lowercase letters, digits, and special characters.

## Requirements

- Python 3.x
- `cryptography` library

## Installation

To install the required libraries, run the following command:

```
pip install cryptography
```

## Running the App

To run the app, execute the following command:

```
python password_manager.py
```

That's it! You now have a simple password manager app that meets your requirements. Let me know if you need any further assistance.
