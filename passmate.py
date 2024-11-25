import os
import mysql.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet, InvalidToken
import bcrypt
import sys
import keyboard


# File to store the encryption key
KEY_FILE = "encryption_key.key"

# Function to load or generate the key


def masked_input(prompt="Enter password: "):
    print(prompt, end='', flush=True)
    password = ""

    # Start listening for keypresses
    while True:
        event = keyboard.read_event(suppress=True)  # Suppress echoes to the terminal
        if event.event_type == "down":  # Only handle key press, not release
            if event.name == "enter":  # Enter key to finish input
                print()  # Move to the next line
                break
            elif event.name == "backspace":  # Handle backspace
                if len(password) > 0:
                    password = password[:-1]
                    # Move the cursor back, overwrite with a space, and move back again
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif len(event.name) == 1:  # Valid character input (ignores special keys)
                password += event.name
                print("*", end='', flush=True)
    return password


def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

# Load the key when the program starts


ENCRYPTION_KEY = get_encryption_key()
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
    encrypted = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = encrypted.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return salt, iv, encrypted_data

# Decrypt data using AES


def decrypt(encrypted_data, password, salt, iv):
    key = load_or_create_aes_key(password, salt)

    encrypted = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = encrypted.decryptor()

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
            print("An user with the same name already exists. Please choose a different username.")
            username = input("Enter a new username: ")  # Prompt user for a different username
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


# Delete a specific password entry for a service
def delete_password(service, user_key):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    try:
        # Retrieve all entries for the given service
        cursor.execute(f"SELECT service, username, password, salt, iv "
                       f"FROM {user_key}_passwords WHERE service = %s", (service,))
        entries = cursor.fetchall()

        if entries:
            print(f"Entries for service '{service}':")
            for idx, entry in enumerate(entries):
                try:
                    # Decrypt the username and password for each entry
                    decrypted_username = cipher.decrypt(entry[1]).decode()
                    decrypted_password = cipher.decrypt(entry[2]).decode()
                    print(f"{idx + 1}. Username: {decrypted_username}, Password: {decrypted_password}\n")
                except InvalidToken:
                    print(f"{idx + 1}. Decryption failed for this entry.")

            while True:
                # Prompt the user to choose an entry to delete or exit
                choice = input(f"Enter the number of the entry to delete (1-{len(entries)}),"
                               f"or type 'exit' to return to the previous menu: ")
                if choice.lower() == 'exit':
                    print("Exiting to the previous menu.\n")
                    return  # Exit the function immediately

                if choice.isdigit():
                    choice = int(choice)
                    if 1 <= choice <= len(entries):
                        # Identify the selected entry
                        selected_entry = entries[choice - 1]
                        encrypted_username = selected_entry[1]
                        encrypted_password = selected_entry[2]

                        # Delete the selected entry
                        cursor.execute(
                            f"DELETE FROM {user_key}_passwords WHERE service = %s AND username = %s AND password = %s",
                            (service, encrypted_username, encrypted_password)
                        )
                        connection.commit()
                        print(f"\nPassword entry {choice} for service '{service}' has been deleted.")
                        break  # Exit the loop after a successful deletion
                    else:
                        print("Invalid selection. Please try again.\n")
                else:
                    print("Invalid input. Please try again.\n")
        else:
            # No entries found for the service, print the message and return to the menu
            print(f"No entries found for service '{service}'. Returning to the previous menu.\n")
            return  # Exit the function immediately
    except mysql.connector.Error as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the cursor and connection are properly closed
        cursor.close()
        connection.close()


# Delete user and all their data


def delete_user(username, password):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    try:
        # Authenticate the user
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user[0].encode()):
            # Double confirmation
            print("Are you sure you want to delete your account? This action is irreversible.")
            confirm1 = input("Type 'DELETE' to confirm (type anything else to cancel): ")
            if confirm1 == "DELETE":
                confirm2 = input("Type 'CONFIRM' to finalize (type anything else to cancel): ")
                if confirm2 == "CONFIRM":
                    # Drop the user's passwords table
                    cursor.execute(f"DROP TABLE IF EXISTS {username}_passwords")

                    # Delete the user from the users table
                    cursor.execute("DELETE FROM users WHERE username = %s", (username,))
                    connection.commit()

                    print(f"User '{username}' and all associated data have been deleted.")
                else:
                    print("Account deletion canceled.")
            else:
                print("Account deletion canceled.")
        else:
            print("Authentication failed. Cannot delete account.")
    except mysql.connector.Error as e:
        print(f"An error occurred: {e}")
    finally:
        cursor.close()
        connection.close()


def main():
    while True:
        print("\nWelcome to the PassMate Password Manager!\n")
        print("1. Log into an existing user")
        print("2. Create a new user")
        print("3. Exit the program\n")
        choice = input("Select an option (1-3): ")

        if choice == "1":
            username = input("\nEnter Your username: ")
            password = masked_input("Enter Your password: ")

            if authenticate_user(username, password):
                print("\nAuthentication successful!")
                password_key = username

                while True:
                    print("\nOptions:")
                    print("1. Add a new entry to PassMate")
                    print("2. Retrieve credentials from the database")
                    print("3. View saved a list of entries in the database")
                    print("4. Delete an entry ")
                    print("5. Delete the account")
                    print("6. Log out\n")
                    choice = input("Select an option: ")
                    print("\n")

                    if choice == "1":
                        service = input("Enter the service name (Google, Steam, Discord, etc.): ")
                        service_username = input("Enter the username: ")
                        service_password = masked_input("Enter the password: ")
                        save_password(service, service_username, service_password, password_key)
                        print("Password saved successfully!")

                    elif choice == "2":
                        service = input("Enter the service name: ")
                        retrieve_password(service, password_key)

                    elif choice == "3":
                        list_services(password_key)

                    elif choice == "4":
                        service = input("Enter the service entry to delete: ")
                        delete_password(service, password_key)

                    elif choice == "5":
                        delete_user(username, password)
                        break  # Exit to the main menu after account deletion

                    elif choice == "6":
                        print("Goodbye!")
                        break

                    else:
                        print("Invalid option, please try again.")

            else:
                print("\nAuthentication failed!")

        elif choice == "2":
            while True:
                username = input("Enter a new username: ")
                if not user_exists(username):  # Check if the username already exists
                    password = masked_input("Enter a new password: ")
                    if create_new_user(username, password):
                        print(f"New user '{username}' created successfully! You may log in now")
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
