import os
import json
import mysql.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import bcrypt

ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# MySQL connection
def get_db_connection(database=None):
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        port=3308
    )

    if database:
        cursor = connection.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
        connection.commit()
        connection.database = database

    return connection

# Create table for user-specific data (password storage table)
def create_user_table(username):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS {username}_passwords (
        service VARCHAR(255) NOT NULL,
        username BLOB NOT NULL,
        password BLOB NOT NULL,
        salt VARBINARY(16) NOT NULL,
        iv VARBINARY(16) NOT NULL
    )
    """)

    connection.commit()
    connection.close()

# Generate or load AES encryption key from password
def load_or_create_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encrypt data using AES
def encrypt(data, password):
    salt = os.urandom(16)
    key = load_or_create_aes_key(password, salt)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return salt, iv, encrypted_data

# Decrypt data using AES
def decrypt(encrypted_data, password, salt, iv):
    key = load_or_create_aes_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return original_data.decode()

# MySQL Authentication
def authenticate_user(username, password):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    connection.close()

    if user and bcrypt.checkpw(password.encode(), user[0].encode()):
        return True
    return False

# Create a new user in the database
def create_new_user(username, password):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    # Check if the user already exists
    while True:
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            print("Username already exists. Please choose a different username.")
            username = input("Enter your username: ")  # Prompt user for a different username
        else:
            break  # Exit the loop if the username is not taken

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        connection.commit()
        create_user_table(username)
    except mysql.connector.Error as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        connection.close()

    return True


# Save password to MySQL database
def save_password(service, username, password, user_key):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    create_user_table(user_key)

    encrypted_username = cipher.encrypt(username.encode())
    encrypted_password = cipher.encrypt(password.encode())

    cursor.execute(f"""
    INSERT INTO {user_key}_passwords (service, username, password, salt, iv)
    VALUES (%s, %s, %s, %s, %s)
    """, (service, encrypted_username, encrypted_password, b'', b''))

    connection.commit()
    connection.close()

# Retrieve all passwords for a service
def retrieve_password(service, user_key):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    # Retrieve all entries for the given service
    cursor.execute(f"SELECT username, password FROM {user_key}_passwords WHERE service = %s", (service,))
    entries = cursor.fetchall()

    connection.close()

    if entries:
        print(f"Passwords for service '{service}':")
        for entry in entries:
            try:
                # Decrypt the username and password for each entry
                username = cipher.decrypt(entry[0])
                password = cipher.decrypt(entry[1])
                print(f"Username: {username.decode()}, Password: {password.decode()}")
            except InvalidToken:
                print("Decryption failed. The data might be corrupted or the key is incorrect.")
    else:
        print(f"No passwords found for the service '{service}'.")


# List all services the user has passwords saved for
def list_services(password_key):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    cursor.execute(f"SELECT service FROM {password_key}_passwords")
    services = cursor.fetchall()

    connection.close()

    if services:
        print("Your saved services:")
        for service in services:
            print(service[0])
    else:
        print("No services found.")


# Check if a user exists in the database
def user_exists(username):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    connection.close()

    return user is not None

# Delete a password for a service
def delete_password(service, user_key):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    try:
        # Check if the service exists for the given user
        cursor.execute(f"SELECT service FROM {user_key}_passwords WHERE service = %s", (service,))
        service_exists = cursor.fetchone()

        # Clear any remaining results in the cursor
        cursor.fetchall()

        if service_exists:
            # If the service exists, delete the password entry for the given service
            cursor.execute(f"DELETE FROM {user_key}_passwords WHERE service = %s", (service,))
            connection.commit()
            print(f"Password entry for '{service}' has been deleted.")
        else:
            # If the service doesn't exist, inform the user
            print(f"Service '{service}' not found. No password entry was deleted.")
    except mysql.connector.Error as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the cursor and connection are properly closed
        cursor.close()
        connection.close()




def main():
    while True:
        print("Welcome to the Password Manager!")
        print("1. Existing user")
        print("2. Create new user")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Enter your username: ")
            password = input("Enter your password: ")

            if authenticate_user(username, password):
                print("Authentication successful!")
                password_key = username

                while True:
                    print("\nOptions:")
                    print("1. Add a new password")
                    print("2. Retrieve a password")
                    print("3. View saved services")
                    print("4. Delete a password")
                    print("5. Exit")
                    choice = input("Enter your choice: ")

                    if choice == "1":
                        service = input("Enter the service name: ")
                        service_username = input("Enter the username: ")
                        service_password = input("Enter the password: ")
                        save_password(service, service_username, service_password, password_key)
                        print("Password saved successfully!")

                    elif choice == "2":
                        service = input("Enter the service name: ")
                        retrieve_password(service, password_key)

                    elif choice == "3":
                        list_services(password_key)

                    elif choice == "4":
                        service = input("Enter the service name to delete: ")
                        delete_password(service, password_key)

                    elif choice == "5":
                        print("Goodbye!")
                        break

                    else:
                        print("Invalid option, please try again.")
            else:
                print("Authentication failed!")




        elif choice == "2":
            while True:
                username = input("Enter your username: ")
                if not user_exists(username):  # Check if the username already exists
                    password = input("Enter your password: ")
                    if create_new_user(username, password):
                        print(f"New user {username} created successfully!")
                        break  # Exit the loop after successful user creation
                else:
                    print("Username already exists. Please choose a different username.")


        elif choice == "3":
            print("Exiting the Password Manager...")
            break

        else:
            print("Invalid option, please try again.")


if __name__ == "__main__":
    get_db_connection('passmate')
    main()
