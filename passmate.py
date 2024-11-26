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
import re


# File to store the encryption key
KEY_FILE = "encryption_key.key"

# Function to load or generate the key


def validate_string(input_str, validation_type):
    """
    Validates strings based on the given validation type.
    Returns a tuple (valid, result). `valid` is a boolean indicating success, and `result` is either
    the sanitized value (on success) or an error message (on failure).
    """
    # Common length constraints
    max_length = 50  # Default maximum length for strings

    # Adjust constraints based on the validation type
    if validation_type == "username":
        min_length = 3
        allowed_chars = r"^[a-zA-Z0-9_\-\.@]+$"  # Alphanumeric, underscores, dashes, dots, and @ for emails
    elif validation_type == "password":
        min_length = 3
        allowed_chars = r"^[a-zA-Z0-9_\-\.@/!#$%^&*()+=<>?;:,.&|~`'\"-_/+ ]+$"  # Alphanumeric, symbols, and punctuation
    elif validation_type == "service":
        min_length = 2
        # Allow alphanumeric, space, period, comma, hyphen, and plus
        allowed_chars = r"^[a-zA-Z0-9_\-\.\/, \+]+$"  # Alphanumeric, symbols (including `.,-+/`)
    else:
        return False, "Invalid validation type provided."

    # Strip surrounding whitespace
    input_str = input_str.strip()

    # Validate length
    if len(input_str) < min_length:
        return False, f"{validation_type.capitalize()} must be at least {min_length} characters long."
    if len(input_str) > max_length:
        return False, f"{validation_type.capitalize()} cannot exceed {max_length} characters."

    # Validate allowed characters
    if not re.match(allowed_chars, input_str):
        return False, f"{validation_type.capitalize()} contains invalid characters." \
                      f"Only letters, digits, and specific symbols like ,.-'/+ are allowed." \
                      f"Username and password cannot contain spaces."

    return True, input_str


def validate_number(choice_str, max_value):
    """
    Sanitizes and validates the input to ensure it's a valid number within the allowed range.
    Returns a tuple (valid, choice), where valid is a boolean and choice is either an integer or an error message.
    """
    # Check if the input is 'exit'
    if isinstance(choice_str, str) and choice_str.lower() == 'exit':
        return True, 'exit'

    # Try to convert the input to an integer
    try:
        choice = int(choice_str)  # Convert to integer
        # Check if it's within the valid range
        if 1 <= choice <= max_value:
            return True, choice
        else:
            return False, f"Please enter a number between 1 and {max_value}."
    except ValueError:
        return False, "Invalid input. Please enter a valid number."


# Sanitization before saving in database (ensure proper encoding and handling)


def sanitize_string(input_string):
    # Remove leading and trailing spaces
    sanitized_input = input_string.strip()

    # Optionally, you can also escape or remove any dangerous characters
    # Here we allow only ASCII characters for simplicity (you can expand this if needed)
    sanitized_input = re.sub(r'[^\x00-\x7F]+', '', sanitized_input)  # Removes non-ASCII characters

    return sanitized_input


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
def create_user_table(username=None):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    # Ensure the 'users' table is created with correct collation
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(255) COLLATE utf8mb4_general_ci PRIMARY KEY,
        password BLOB NOT NULL
    )
    """)
    connection.commit()

    if username:
        # Create the table for storing passwords for this user
        cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {username}_passwords (
            service VARCHAR(255) COLLATE utf8mb4_general_ci NOT NULL,
            username BLOB NOT NULL,
            password BLOB NOT NULL,
            salt VARBINARY(16) NOT NULL,
            iv VARBINARY(16) NOT NULL,
            -- Relaxed constraint for service length
            CONSTRAINT service_length CHECK (CHAR_LENGTH(service) >= 3),  
            -- Relaxed constraint for username length
            CONSTRAINT username_length CHECK (CHAR_LENGTH(username) >= 3), 
            -- Relaxed constraint for password length
            CONSTRAINT password_length CHECK (CHAR_LENGTH(password) >= 3)  
        )
        """)
        connection.commit()

    connection.close()  # Closing connection once after all the queries are done


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
    username = sanitize_string(username)  # Sanitize input
    password = sanitize_string(password)  # Sanitize input
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    connection.close()

    # Corrected: Remove .encode() on user[0]
    if user and bcrypt.checkpw(password.encode(), user[0]):
        return True
    return False


# Create a new user in the database


def create_new_user(username, password):
    username = sanitize_string(username)  # Sanitize username
    password = sanitize_string(password)  # Sanitize password

    if len(username) < 2:
        print("Error: Username must be at least 2 characters long.")
        return False

    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    try:
        # Check if the username already exists in the database
        cursor.execute("SELECT username FROM users WHERE username = %s COLLATE utf8mb4_general_ci", (username,))
        user = cursor.fetchone()
        if user:
            print("Username already exists.")
            return False

        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # Proceed with user creation (insert the username and hashed password)
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        connection.commit()

        print(f"User '{username}' created successfully.")
        connection.close()
        return True

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        connection.close()
        return False


# Save password to MySQL database
def save_password(service, username, password, user_key):
    # Validate inputs
    valid_service, msg_service = validate_string(service, "service")
    valid_username, msg_username = validate_string(username, "username")
    valid_password, msg_password = validate_string(password, "password")

    if not valid_service:
        print(msg_service)
        return
    if not valid_username:
        print(msg_username)
        return
    if not valid_password:
        print(msg_password)
        return

    # Sanitize strings before saving
    service = sanitize_string(service)
    username = sanitize_string(username)
    password = sanitize_string(password)

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


def retrieve_password(user_key, service):
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
def list_services(user_key):
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    try:
        # Check if the table exists
        cursor.execute(f"SHOW TABLES LIKE '{user_key}_passwords'")
        result = cursor.fetchone()

        if result:  # Table exists
            cursor.execute(f"SELECT service FROM {user_key}_passwords")
            services = cursor.fetchall()

            if services:
                print("Services stored in PassMate:")
                for idx, service in enumerate(services, start=1):
                    print(f"{idx}. {service[0]}")
            else:
                print("No services stored yet.")
        else:
            print(f"No password entries found for user {user_key}. Please add some services first.")

    except mysql.connector.Error as e:
        print(f"An error occurred: {e}")
    finally:
        cursor.close()
        connection.close()


# Check if a user exists in the database
def user_exists(username):
    """
    Checks if the user exists in the 'users' table.
    If the 'users' table does not exist, it creates the table.
    """
    connection = get_db_connection('passmate')
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        connection.close()

        return user is not None

    except mysql.connector.errors.ProgrammingError as e:
        # If table doesn't exist, create the users table
        if '1146' in str(e):  # MySQL-error code for "Table doesn't exist"
            print("Users table does not exist. Creating it now...")
            create_user_table(None)  # No need to pass username here; it's the table creation
            return False  # Return False as no users exist yet
        else:
            print(f"An error occurred: {e}")
            connection.close()
            return False


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
                    print(f"{idx + 1}. Username: {decrypted_username}, Password: {decrypted_password}")
                except InvalidToken:
                    print(f"{idx + 1}. Decryption failed for this entry.")

            while True:
                # Prompt the user to choose an entry to delete or exit
                choice_str = input(f"\nEnter the number of the entry to delete (1-{len(entries)}), "
                                   f"or type 'exit' to return to the previous menu: ")

                valid, choice = validate_number(choice_str, len(entries))
                if valid:
                    if choice == 'exit':
                        print("Exiting to the previous menu.\n")
                        return  # Exit the function immediately

                    # Proceed with deletion
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
                    print(choice)  # Print the error message from `validate_number`

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
        # Retrieve the user's password from the database for verification
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user[0]):  # No need for user[0].encode()
            # Ask for confirmation
            print(f"\nWARNING: You are about to delete the account for '{username}'.")
            print("This action cannot be undone. All data will be permanently deleted.\n")
            confirmation = input("Type 'DELETE' to confirm account deletion, or 'CANCEL' to abort: ").strip().upper()

            if confirmation == 'DELETE':
                # Proceed with account deletion
                cursor.execute("DELETE FROM users WHERE username = %s", (username,))
                cursor.execute(f"DROP TABLE IF EXISTS {username}_passwords")  # Drop the user's passwords table
                connection.commit()
                print(f"Account for user '{username}' has been deleted successfully.")

                # After deletion, log out and return to the previous menu (the logged-in menu)
                return "Account deleted. Returning to the login menu."

            else:
                return "\nAccount deletion canceled."
        else:
            print("Password does not match. Account deletion aborted.")
            return "Password does not match. Account deletion aborted."

    except mysql.connector.Error as e:
        print(f"An error occurred: {e}")
        return "An error occurred while deleting the account."

    finally:
        cursor.close()
        connection.close()


def main():
    while True:
        print("\nWelcome to the PassMate Password Manager!\n")
        print("1. Log into an existing user")
        print("2. Create a new user")
        print("3. Exit the program\n")

        # Validate the main menu choice
        valid, choice = validate_number(input("Select an option (1-3): "), 3)
        if not valid:
            print(choice)  # Display error message from `validate_number`
            continue

        if choice == 1:
            # Log in process
            username = input("\nEnter your username (or type 'exit' to return to the main menu): ")
            if username.lower() == 'exit':
                print("Returning to the main menu.")
                continue  # Go back to the main menu

            valid, username = validate_string(username, "username")
            if not valid:
                print(username)  # Display error message from `validate_string`
                continue

            password = masked_input("Enter your password (or type 'exit' to return to the main menu): ")
            if password.lower() == 'exit':
                print("Returning to the main menu.")
                continue  # Go back to the main menu

            valid, password = validate_string(password, "password")
            if not valid:
                print(password)  # Display error message from `validate_string`
                continue

            if authenticate_user(username, password):
                print("\nAuthentication successful!")
                password_key = username

                while True:
                    print("\nOptions:")
                    print("1. Add a new entry to PassMate")
                    print("2. Retrieve credentials from the database")
                    print("3. View saved entries in the database")
                    print("4. Delete an entry")
                    print("5. Delete the account")
                    print("6. Log out\n")

                    valid, choice = validate_number(input("Select an option (1-6): "), 6)
                    if not valid:
                        print(choice)
                        continue

                    if choice == 1:
                        # Add a new entry
                        service = input("Enter the service name (or type 'exit' to return to the main menu): ")
                        if service.lower() == 'exit':
                            print("Returning to the previous menu.")
                            break  # Go back to the previous menu
                        valid, service = validate_string(service, "service")
                        if not valid:
                            print(service)
                            continue

                        service_username = input("Enter the username (or type 'exit' to return to the previous menu): ")
                        if service_username.lower() == 'exit':
                            print("Returning to the previous menu.")
                            break  # Go back to the previous menu
                        valid, service_username = validate_string(service_username, "username")
                        if not valid:
                            print(service_username)
                            continue

                        service_password = masked_input("Enter the password (or type 'exit' to return to the previous menu): ")
                        if service_password.lower() == 'exit':
                            print("Returning to the previous menu.")
                            break  # Go back to the previous menu
                        valid, service_password = validate_string(service_password, "password")
                        if not valid:
                            print(service_password)
                            continue

                        save_password(service, service_username, service_password, password_key)
                        print("Password saved successfully!")

                    elif choice == 2:
                        service = input("Enter the service entry to retrieve credentials: ")
                        valid, service = validate_string(service, "service")
                        if not valid:
                            print(service)
                            continue
                        retrieve_password(password_key, service)

                    elif choice == 3:
                        list_services(password_key)

                    elif choice == 4:
                        service = input("Enter the service entry to delete (or type 'exit' to return to the previous menu): ")
                        if service.lower() == 'exit':
                            print("Returning to the previous menu.")
                            break  # Go back to the previous menu
                        valid, service = validate_string(service, "service")
                        if not valid:
                            print(service)
                            continue
                        delete_password(service, password_key)

                    elif choice == 5:
                        result = delete_user(username, password)
                        print(result)  # This will print either "Account deleted" or "Account deletion canceled"
                        if "deleted" in result.lower():
                            # Account was deleted, so return to the main menu (log out the user)
                            print("Logging out and returning to the main menu...")
                            break  # Exit to the main menu

                        elif "canceled" in result.lower():
                            # Deletion was canceled, stay logged in
                            print("Returning to the menu...\n")
                            continue  # Stay logged in

                    elif choice == 6:
                        print("Logging out...")
                        break  # Exit to the main menu

            else:
                print("\nAuthentication failed!")

        elif choice == 2:
            # User creation process
            while True:
                username = input("Enter a new username (or type 'exit' to return to the main menu): ")
                if username.lower() == 'exit':
                    print("Returning to the main menu.")
                    break  # Go back to the main menu
                valid, username = validate_string(username, "username")
                if not valid:
                    print(username)
                    continue

                if not user_exists(username):
                    password = masked_input("Enter a new password (or type 'exit' to return to the main menu): ")
                    if password.lower() == 'exit':
                        print("Returning to the main menu.")
                        break  # Go back to the main menu
                    valid, password = validate_string(password, "password")
                    if not valid:
                        print(password)
                        continue

                    if create_new_user(username, password):
                        print(f"New user '{username}' created successfully! You may log in now.")
                        break  # Exit to the main menu
                else:
                    print("Username already exists. Please choose a different username.")

        elif choice == 3:
            print("Exiting the Password Manager.")
            break  # Exit the program

        else:
            print("Invalid option, please try again.")


if __name__ == "__main__":
    get_db_connection('passmate')
    main()