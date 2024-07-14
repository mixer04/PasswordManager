import os
import json
from cryptography.fernet import Fernet
from getpass import getpass
import secrets
import string
import re
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import InvalidToken

class PasswordManager:
    def __init__(self, master_password):
        # File paths for key and passwords storage
        self.key_file = 'encrypted_key.key'
        self.passwords_file = 'passwords.json'
        self.master_password = master_password
        
        # Load or create the encryption key
        self.key = self.load_or_create_key(master_password)
        
        # If the key is invalid, raise an error
        if not self.key:
            raise ValueError("Invalid master password. Exiting.")
        
        # Initialize an empty dictionary for passwords
        self.passwords = {}

    def load_or_create_key(self, master_password):
        # Check if the key file exists
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as file:
                # Read the salt and the encrypted key
                salt = file.read(16)
                encrypted_key = file.read()
            try:
                # Attempt to decrypt the key using the master password and salt
                return self.decrypt_key(encrypted_key, master_password, salt)
            except InvalidToken:
                # Return None if decryption fails
                return None
        else:
            # Generate a new key and salt
            key = Fernet.generate_key()
            salt = os.urandom(16)
            encrypted_key = self.encrypt_key(key, master_password, salt)
            # Write the salt and encrypted key to the key file
            with open(self.key_file, 'wb') as file:
                file.write(salt + encrypted_key)
            return key

    def encrypt_key(self, key, master_password, salt):
        # Derive a Fernet key from the master password and salt using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_fernet = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        fernet = Fernet(key_fernet)
        # Encrypt the generated key using the derived Fernet key
        return fernet.encrypt(key)

    def decrypt_key(self, encrypted_key, master_password, salt):
        # Derive a Fernet key from the master password and salt using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_fernet = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        fernet = Fernet(key_fernet)
        # Decrypt the encrypted key using the derived Fernet key
        return fernet.decrypt(encrypted_key)

    def add_password(self, service, password):
        # Encrypt the password and store it in the dictionary
        encrypted_password = self.encrypt_password(password)
        self.passwords[service] = encrypted_password
        print(f"Password for {service} added.")

    def get_password(self, service):
        # Retrieve and decrypt the password for the given service
        if service in self.passwords:
            encrypted_password = self.passwords[service]
            return self.decrypt_password(encrypted_password)
        else:
            return None

    def update_password(self, service, new_password):
        # Update the password for the given service
        if service in self.passwords:
            encrypted_password = self.encrypt_password(new_password)
            self.passwords[service] = encrypted_password
            print(f"Password for {service} updated.")
        else:
            print(f"No password found for {service}.")

    def delete_password(self, service):
        # Delete the password for the given service
        if service in self.passwords:
            del self.passwords[service]
            print(f"Password for {service} deleted.")
        else:
            print(f"No password found for {service}.")

    def save_passwords(self):
        # Save the passwords dictionary to a JSON file
        with open(self.passwords_file, 'w') as file:
            json.dump({service: encrypted_password.decode() for service, encrypted_password in self.passwords.items()}, file)
        print("Passwords saved.")

    def load_passwords(self):
        # Load the passwords from a JSON file into the dictionary
        if os.path.exists(self.passwords_file):
            with open(self.passwords_file, 'r') as file:
                passwords = json.load(file)
                self.passwords = {service: encrypted_password.encode() for service, encrypted_password in passwords.items()}
            print("Passwords loaded.")
        else:
            print("No passwords file found.")

    def encrypt_password(self, password):
        # Encrypt a password using the Fernet key
        fernet = Fernet(self.key)
        return fernet.encrypt(password.encode())

    def decrypt_password(self, encrypted_password):
        # Decrypt a password using the Fernet key
        fernet = Fernet(self.key)
        return fernet.decrypt(encrypted_password).decode()

    def generate_password(self, length=12):
        # Generate a random password of the given length
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for i in range(length))
        return password

    def check_password_strength(self, password):
        # Check the strength of a password based on various criteria
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*()_+]", password):
            return False, "Password must contain at least one special character."
        return True, "Password is strong."

    def search_password(self, search_term):
        # Search for passwords containing the search term in their service name
        results = {service: self.decrypt_password(encrypted_password) for service, encrypted_password in self.passwords.items() if search_term in service}
        return results

def main():
    print("Welcome to the Password Manager")
    master_password = getpass("Enter master password: ")
    try:
        manager = PasswordManager(master_password)
    except ValueError as e:
        print(e)
        return

    manager.load_passwords()

    while True:
        print("\n1. Add password")
        print("2. Get password")
        print("3. Update password")
        print("4. Delete password")
        print("5. Generate password")
        print("6. Check password strength")
        print("7. Search password")
        print("8. Save and exit")
        choice = input("Choose an option: ")

        if choice == '1':
            # Add a new password
            service = input("Enter the service name: ")
            password = getpass("Enter the password: ")
            manager.add_password(service, password)
        elif choice == '2':
            # Retrieve a password
            service = input("Enter the service name: ")
            password = manager.get_password(service)
            if password:
                print(f"The password for {service} is {password}")
            else:
                print(f"No password found for {service}")
        elif choice == '3':
            # Update an existing password
            service = input("Enter the service name: ")
            new_password = getpass("Enter the new password: ")
            manager.update_password(service, new_password)
        elif choice == '4':
            # Delete a password
            service = input("Enter the service name: ")
            manager.delete_password(service)
        elif choice == '5':
            # Generate a new password
            length = int(input("Enter the desired password length: "))
            password = manager.generate_password(length)
            print(f"Generated password: {password}")
        elif choice == '6':
            # Check the strength of a password
            password = getpass("Enter the password to check: ")
            strength, message = manager.check_password_strength(password)
            print(message)
        elif choice == '7':
            # Search for a password
            search_term = input("Enter search term: ")
            results = manager.search_password(search_term)
            for service, password in results.items():
                print(f"{service}: {password}")
        elif choice == '8':
            # Save passwords and exit
            manager.save_passwords()
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
