import os
import bcrypt
import keyboard
import logging
import re
import sqlite3
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet, InvalidToken


KEY_FILE = "encryption_key.key"                                                                                         # This is where the encryption key is stored
dupe = "Returning to the main menu."
dupe_db = "Database connection closed."
logging.basicConfig(                                                                                                    # Set up logging
    level=logging.DEBUG,                                                                                                # Debug logs
    format='%(asctime)s - %(levelname)s - %(message)s',                                                                 # Log time, level, message
    filename='log.txt',  # Log file name
    filemode='a'                                                                                                        # Appends, does not overwrite
)


def validate_string(input_str, validation_type):
    """
    Validates strings based on the given validation type.
    Returns:
        - boolean: success or fail
        - result: sanitised value or error message
    """
    try:
        max_length = 50                                                                                                 # Default maximum length for strings

        # Adjust constraints based on the validation type
        if validation_type == "username":
            min_length = 3
            allowed_chars = r"^[a-zA-Z0-9_\-\.@]+$"                                                                     # Alphanumeric, underscores, dashes, dots, and @ for emails
        elif validation_type == "password":
            min_length = 3
            allowed_chars = r"^[a-zA-Z0-9_\-\.@/!#$%^&*()+=<>?;:,.&|~`'\"-_/+ ]+$"                                      # Alphanumeric, symbols, and punctuation
        elif validation_type == "service":
            min_length = 2
            allowed_chars = r"^[a-zA-Z0-9_\-\.\/, \+]+$"                                                                # Alphanumeric, symbols (including `.,-+/`)
        else:
            error_message = "Invalid validation type provided."
            logging.error(error_message)                                                                                # Log the error
            return False, error_message

        input_str = input_str.strip()                                                                                   # Strip surrounding whitespace

        # Validate length
        if len(input_str) < min_length:
            error_message = f"{validation_type.capitalize()} must be at least {min_length} characters long."
            logging.warning(error_message)
            return False, error_message
        if len(input_str) > max_length:
            error_message = f"{validation_type.capitalize()} cannot exceed {max_length} characters."
            logging.warning(error_message)
            return False, error_message

        if not re.match(allowed_chars, input_str):
            error_message = f"{validation_type.capitalize()} contains invalid characters." \
                             f" Only letters, digits, and specific symbols like ,.-'/+ are allowed." \
                             f" Username and password cannot contain spaces."
            logging.warning(error_message)
            return False, error_message

        logging.info(f"{validation_type.capitalize()} validation successful.")
        return True, input_str

    except Exception as e:                                                                                              # Exception handling
        logging.error(f"Error during validation of {validation_type}: {e}", exc_info=True)
        return False, f"An unexpected error occurred while validating {validation_type}."


def validate_number(choice_str, max_value):
    """
    Sanitizes and validates the input to ensure it's a valid number within the allowed range.
    Returns:
        - valid
        - choice

    Parameters:
    - choice_str: The input string to be validated, typically from user input.
    - max_value: The maximum allowed value for the input number (inclusive).

    Returns:
    - A tuple (valid, choice), where valid is a boolean indicating success and
      choice is either a sanitized integer or an error message.
    """
    # Check if the input is 'exit' and return early if so
    if isinstance(choice_str, str) and choice_str.lower() == 'exit':
        logging.info("User chose to exit the menu.")  # Log the 'exit' choice
        return True, 'exit'

    try:
        choice = int(choice_str)  # Convert to integer
        # Check if the choice is within the valid range
        if 1 <= choice <= max_value:
            logging.info(f"User entered a valid choice: {choice}.")  # Log valid input
            return True, choice
        else:
            error_message = f"Please enter a number between 1 and {max_value}."
            logging.warning(error_message)  # Log the invalid range warning
            return False, error_message

    except ValueError:
        # Handle the case where the input cannot be converted to an integer
        error_message = "Invalid input. Please enter a valid number."
        logging.warning(error_message)  # Log the invalid input
        return False, error_message

    except Exception as e:
        # Catch any other unexpected exceptions and log them
        logging.error(f"Unexpected error during validation: {e}", exc_info=True)  # Log unexpected errors
        return False, "An unexpected error occurred while processing your input."


def sanitize_string(input_string):
    """
    Sanitizes a string by removing leading/trailing spaces and non-ASCII characters.

    Parameters:
    - input_string: The raw string that needs to be sanitized.

    Returns:
    - The sanitized string, with non-ASCII characters removed and extra spaces stripped.
    """
    try:
        sanitized_input = input_string.strip()                                                                          # Remove leading and trailing spaces from the input string
        sanitized_input = re.sub(r'[^\x00-\x7F]+', '', sanitized_input)                                                 # Remove any non-ASCII characters
        logging.info(f"Sanitization successful: '{sanitized_input}'")
        return sanitized_input

    except Exception as e:
        logging.error(f"Error sanitizing input string: {e}", exc_info=True)
        return "An error occurred during sanitization."


def masked_input(prompt="Enter password: "):
    """
    Prompts the user for a password input without displaying the entered characters.
    The password is masked with '*' characters as the user types.

    Parameters:
    - prompt: The prompt message to show to the user (default is "Enter password: ").

    Returns:
    - The password entered by the user, without any masking.
    """
    try:
        # Log the start of the password entry process
        logging.info("Password input started.")

        # Display the prompt message
        print(prompt, end='', flush=True)
        password = ""  # Initialize an empty string for the password

        while True:
            event = keyboard.read_event(suppress=True)
            if event.event_type == "down":
                if event.name == "enter":
                    print()
                    break

                elif event.name == "backspace":                                                                         # Handle backspacING
                    if len(password) > 0:
                        password = password[:-1]
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                        logging.debug("Backspace pressed, current password length: %d", len(password))

                elif len(event.name) == 1:                                                                              # Valid character input (ignores special keys)
                    password += event.name                                                                              # Add the character to the password
                    print("*", end='', flush=True)

        return password

    except Exception as e:
        logging.error("Error occurred during masked input: %s", e, exc_info=True)
        return "An error occurred while reading the input."


def get_encryption_key():
    """
    Retrieves the encryption key from a file if it exists, or generates a new one if not.
    Returns:
    - The encryption key as bytes.
    """
    try:
        logging.info(f"Attempting to retrieve encryption key from {KEY_FILE}")

        if os.path.exists(KEY_FILE):                                                                                    # Check if the key file exists
            with open(KEY_FILE, 'rb') as key_file:
                key = key_file.read()
            logging.info(f"Encryption key retrieved from {KEY_FILE}.")
            return key

        else:
            logging.info(f"Key file '{KEY_FILE}' not found. Generating a new encryption key.")
            key = Fernet.generate_key()

            with open(KEY_FILE, 'wb') as key_file:                                                                      # Write the generated key to the file
                key_file.write(key)
            logging.info(f"New encryption key generated and saved to {KEY_FILE}.")
            return key

    except Exception as e:
        logging.error(f"Error occurred while retrieving or generating the encryption key: {e}", exc_info=True)
        return None


ENCRYPTION_KEY = get_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)


def get_db_connection(database=None):
    """
    Establishes a connection to the SQLite database. If the database file does not exist, it will be created.
    Parameters:
    - database: The name of the database (without file extension). If not provided, defaults to 'default'.
    Returns:
    - A connection object to the SQLite database or None if an error occurs.
    """
    try:
        # Set the database file name based on the provided database name or fallback to 'default.db'
        if database:
            db_file = f"{database}.db"
        else:
            db_file = "default.db"                                                                                      # Default database name if no database is provided

        logging.info(f"Attempting to connect to database: {db_file}")

        if not os.path.exists(db_file):                                                                                 # Check if the database file already exists
            logging.info(f"Database file '{db_file}' not found. Creating new database.")

        connection = sqlite3.connect(db_file)
        logging.info(f"Successfully connected to the database: {db_file}")
        return connection

    except sqlite3.Error as e:
        logging.error(f"Error occurred while connecting to the database: {e}", exc_info=True)
        return None


def create_user_table(username):
    """
    Creates the necessary database tables for a new user in the 'passmate' database.
    The function will create a 'users' table to store user credentials and a user-specific
    passwords table to store the user's service credentials.
    Args:
    - username (str): The username of the new user for whom the password table is created.
    """
    connection = None
    cursor = None
    try:
        connection = get_db_connection('passmate')
        cursor = connection.cursor()
        logging.info("Creating the 'users' table if it doesn't already exist.")

        # Create the 'users' table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password BLOB NOT NULL
        )
        """)

        if username:
            logging.info(f"Creating the user-specific table for {username}_passwords if it doesn't already exist.")

            # Create the user-specific passwords table
            cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {username}_passwords (
                service  TEXT          NOT NULL,
                username BLOB          NOT NULL,
                password BLOB          NOT NULL,
                salt     VARBINARY(16) NOT NULL,
                iv       VARBINARY(16) NOT NULL,
                
                CONSTRAINT service_length  CHECK (LENGTH(service)  >= 3),
                CONSTRAINT username_length CHECK (LENGTH(username) >= 3), 
                CONSTRAINT password_length CHECK (LENGTH(password) >= 3)  
            )
            """)

        connection.commit()
        logging.info("Tables created successfully.")

    except sqlite3.Error as e:
        logging.error(f"Database error occurred while creating tables: {e}", exc_info=True)

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)

    finally:                                                                                                            # Ensure that the cursor and connection are closed properly
        if cursor:
            cursor.close()
        if connection:
            connection.close()
        logging.info(dupe_db)


def load_or_create_aes_key(password, salt):
    """
    Derives an AES key from the password and salt using PBKDF2 HMAC.
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),                                                                                      # Hashed and encrypted
        length=32,                                                                                                      # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())                                                                                 # Use password to derive key
    return key


def encrypt(data, password):
    """
    Encrypt data using AES with GCM mode and PKCS7 padding.
    Returns the salt, IV, encrypted data, and authentication tag.
    """
    salt = os.urandom(16)                                                                                               # Generate random salt for key derivation
    key = load_or_create_aes_key(password, salt)                                                                        # Derive the key from the password and salt
    iv = os.urandom(12)                                                                                                 # GCM uses a 12-byte nonce (IV)
    secret = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())                                      # Create the AES cipher object in GCM mode
    padder = padding.PKCS7(128).padder()                                                                                # Pad data to be a multiple of the block size (16 bytes for AES)
    padded_data = padder.update(data.encode()) + padder.finalize()
    encryptor = secret.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag
    return salt, iv, encrypted_data, tag


def decrypt(encrypted_data, password, salt, iv, tag):
    """
    Decrypt data using AES with GCM mode and PKCS7 padding.
    Returns the decrypted data as a string.
    """
    key = load_or_create_aes_key(password, salt)                                                                        # Derive the key from the password and salt
    secret = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = secret.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()                                                                            # Remove padding after decryption
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return original_data.decode()


def authenticate_user(username, password):
    """
    Authenticates a user by checking the provided username and password against the stored credentials in the database.

    Args:
    - username (str): The username of the user attempting to log in.
    - password (str): The password provided by the user attempting to log in.

    Returns:
    - bool: True if the user is authenticated successfully, False otherwise.
    """
    username = sanitize_string(username)
    password = sanitize_string(password)

    try:
        # Establish a database connection
        connection = get_db_connection('passmate')
        cursor = connection.cursor()

        # Log the authentication attempt
        logging.info(f"Attempting to authenticate user '{username}'.")

        # Query the database for the stored password for the given username
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        connection.close()

        if user:
            if bcrypt.checkpw(password.encode(), user[0]):
                logging.info(f"User '{username}' authenticated successfully.")
                return True
            else:
                logging.warning(f"Failed authentication attempt for user '{username}'. Incorrect password.")
        else:
            logging.warning(f"Failed authentication attempt. User '{username}' not found.")

    except sqlite3.Error as e:
        logging.error(f"Database error occurred while authenticating user '{username}': {e}", exc_info=True)
    except Exception as e:
        logging.error(f"An unexpected error occurred while authenticating user '{username}': {e}", exc_info=True)

    return False


def create_new_user(username, password):
    """
    Creates a new user by inserting their username and hashed password into the database.

    Args:
    - username (str): The username of the user to be created.
    - password (str): The password of the user to be hashed and stored.

    Returns:
    - bool: True if the user is created successfully, False otherwise.
    """
    username = sanitize_string(username)
    password = sanitize_string(password)

    if len(username) < 2:
        logging.warning(f"Failed to create user. Username '{username}' is too short (must be at least 2 characters).")
        print("Error: Username must be at least 2 characters long.")
        return False

    connection = None
    try:
        connection = get_db_connection('passmate')
        cursor = connection.cursor()
        logging.info(f"Attempting to create a new user with username '{username}'.")
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user:
            logging.warning(f"Username '{username}' already exists in the database.")
            print("Username already exists.")
            return False

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        connection.commit()
        logging.info(f"User '{username}' created successfully.")
        print(f"User '{username}' created successfully.")

    except sqlite3.Error as err:
        logging.error(f"SQLite error occurred while creating user '{username}': {err}", exc_info=True)
        print(f"Error: {err}")
        return False

    except Exception as err:
        logging.error(f"Unexpected error occurred while creating user '{username}': {err}", exc_info=True)
        print(f"Error: {err}")
        return False

    finally:
        if connection:
            connection.close()
            logging.info(dupe_db)

    return True


def save_password(service, username, password, user_key):
    """
    Saves a user's password for a specific service, encrypting both the username and password before storing.

    Args:
    - service (str): The name of the service the password is for (e.g., 'Facebook').
    - username (str): The username for the service.
    - password (str): The password for the service.
    - user_key (str): The username of the user, used as part of the table name for unique storage.
    """
    # Validate inputs for service, username, and password
    valid_service, msg_service = validate_string(service, "service")
    valid_username, msg_username = validate_string(username, "username")
    valid_password, msg_password = validate_string(password, "password")

    if not valid_service:
        logging.warning(f"Service validation failed for '{service}': {msg_service}")
        print(msg_service)
        return
    if not valid_username:
        logging.warning(f"Username validation failed for '{username}': {msg_username}")
        print(msg_username)
        return
    if not valid_password:
        logging.warning(f"Password validation failed for '{username}': {msg_password}")
        print(msg_password)
        return

    service = sanitize_string(service)
    username = sanitize_string(username)
    password = sanitize_string(password)

    connection = None
    try:
        connection = get_db_connection('passmate')
        cursor = connection.cursor()
        logging.info(f"Saving password for service '{service}' under user '{user_key}'.")
        create_user_table(user_key)
        encrypted_username = cipher.encrypt(username.encode())
        encrypted_password = cipher.encrypt(password.encode())
        cursor.execute(f"""
            INSERT INTO {user_key}_passwords (service, username, password, salt, iv)
            VALUES (?, ?, ?, ?, ?)
            """, (service, encrypted_username, encrypted_password, b'', b''))
        connection.commit()
        logging.info(f"Password for service '{service}' saved successfully for user '{user_key}'.")

    except sqlite3.Error as err:
        logging.error(f"SQLite error occurred while saving password for service '{service}'"
                      f"for user '{user_key}': {err}", exc_info=True)
        print(f"Error: {err}")

    except Exception as err:
        logging.error(f"Unexpected error occurred while saving password for service '{service}'"
                      f"for user '{user_key}': {err}", exc_info=True)
        print(f"Error: {err}")

    finally:
        if connection:
            connection.close()
            logging.info(dupe_db)


def retrieve_password(user_key, service):
    """
    Retrieves and decrypts the passwords associated with a specific service for the given user.

    Args:
    - user_key (str): The username of the user.
    - service (str): The service name for which the password is retrieved.
    """
    connection = None
    try:
        connection = get_db_connection('passmate')
        cursor = connection.cursor()
        cursor.execute(f"SELECT username, password FROM {user_key}_passwords WHERE service = ?", (service,))
        entries = cursor.fetchall()

        if entries:
            logging.info(f"Retrieved {len(entries)} entries for service '{service}' for user '{user_key}'.")
            print(f"Passwords for service '{service}':")
            for entry in entries:
                try:
                    username = cipher.decrypt(entry[0])
                    password = cipher.decrypt(entry[1])
                    print(f"Username: {username.decode()}, Password: {password.decode()}")
                except InvalidToken:
                    logging.error(f"Decryption failed for service '{service}'"
                                  f"for user '{user_key}'. Data might be corrupted.")
                    print("Decryption failed. The data might be corrupted or the key is incorrect.")
        else:
            logging.warning(f"No passwords found for service '{service}' for user '{user_key}'.")
            print(f"No passwords found for the service '{service}'.")
    except sqlite3.Error as e:
        logging.error(f"SQLite error occurred while retrieving passwords for service '{service}'"
                      f"for user '{user_key}': {e}", exc_info=True)
        print(f"An error occurred: {e}")
    finally:
        if connection:
            connection.close()


def list_services(user_key):
    """
    Lists all services the user has saved passwords for.

    Args:
    - user_key (str): The username of the user.
    """
    connection = None
    try:
        connection = get_db_connection('passmate')
        cursor = connection.cursor()
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{user_key}_passwords'")
        result = cursor.fetchone()

        if result:
            cursor.execute(f"SELECT service FROM {user_key}_passwords")
            services = cursor.fetchall()

            if services:
                logging.info(f"Retrieved {len(services)} services for user '{user_key}'.")
                print("Services stored in PassMate:")
                for idx, service in enumerate(services, start=1):
                    print(f"{idx}. {service[0]}")
            else:
                logging.info(f"No services stored for user '{user_key}'.")
                print("No services stored yet.")
        else:
            logging.warning(f"No password entries found for user '{user_key}'.")
            print(f"No password entries found for user {user_key}. Please add some services first.")

    except sqlite3.Error as e:
        logging.error(f"An error occurred while listing services for user '{user_key}': {e}", exc_info=True)
        print(f"An error occurred: {e}")
    finally:
        if connection:
            connection.close()


def user_exists(username):
    """
    Checks if the user exists in the 'users' table. Creates the table if it does not exist.

    Args:
    - username (str): The username to check for existence in the 'users' table.
    """
    connection = None
    cursor = None
    try:
        connection = get_db_connection('passmate')
        cursor = connection.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            logging.info(f"User '{username}' exists in the database.")
            return True
        else:
            logging.info(f"User '{username}' does not exist.")
            return False
    except sqlite3.OperationalError as e:
        if 'no such table' in str(e):
            logging.warning("Users table does not exist. Creating it now...")
            create_user_table(None)
            return False
        else:
            logging.error(f"An error occurred while checking user existence: {e}", exc_info=True)
            return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def fetch_entries(cursor, service, user_key):
    """
    Fetches password entries for a specific service from the database.

    Args:
    - cursor: The database cursor object.
    - service (str): The service name.
    - user_key (str): The username of the user.

    Returns:
    - list: A list of entries for the given service.
    """
    cursor.execute(f"SELECT service, username, password, salt, iv "
                   f"FROM {user_key}_passwords WHERE service = ?", (service,))
    return cursor.fetchall()


def print_entries(entries):
    """
    Prints the decrypted entries in a readable format.

    Args:
    - entries (list): List of password entries to print.
    """
    for idx, entry in enumerate(entries):
        try:
            decrypted_username = cipher.decrypt(entry[1]).decode()
            decrypted_password = cipher.decrypt(entry[2]).decode()
            print(f"{idx + 1}. Username: {decrypted_username}, Password: {decrypted_password}")
        except InvalidToken:
            logging.error(f"Decryption failed for entry {idx + 1}. Data might be corrupted.")
            print(f"{idx + 1}. Decryption failed for this entry.")


def get_user_choice(entries):
    """
    Prompts the user to select an entry for deletion.

    Args:
    - entries (list): List of entries to choose from.

    Returns:
    - int or None: The index of the selected entry, or None if the user exits.
    """
    while True:
        choice_str = input(f"\nEnter the number of the entry to delete (1-{len(entries)}), "
                           f"or type 'exit' to return to the previous menu: ")
        valid, choice = validate_number(choice_str, len(entries))
        if valid:
            if choice == 'exit':
                print("Exiting to the previous menu.\n")
                return None
            return choice
        else:
            print(choice)


def delete_password(service, user_key):
    """
    Deletes a password entry for a specific service.

    Args:
    - service (str): The service for which to delete the password.
    - user_key (str): The username of the user.
    """
    connection = None
    cursor = None
    try:
        connection = get_db_connection('passmate')
        cursor = connection.cursor()

        entries = fetch_entries(cursor, service, user_key)

        if not entries:
            logging.warning(f"No entries found for service '{service}' for user '{user_key}'.")
            print(f"No entries found for service '{service}'. Returning to the previous menu.\n")
            return

        print(f"Entries for service '{service}':")
        print_entries(entries)

        choice = get_user_choice(entries)
        if choice is None:
            return

        selected_entry = entries[int(choice) - 1]
        decrypted_username = selected_entry[1]
        decrypted_password = selected_entry[2]
        cursor.execute(f"DELETE FROM {user_key}_passwords WHERE service = ? AND username = ? AND password = ?",
                       (service, decrypted_username, decrypted_password))
        connection.commit()

        logging.info(f"Password entry for service '{service}' has been deleted for user '{user_key}'.")
        print(f"\nPassword entry {choice} for service '{service}' has been deleted.")

    except sqlite3.Error as e:
        logging.error(f"An error occurred while deleting password for service '{service}'"
                      f"for user '{user_key}': {e}", exc_info=True)
        print(f"An error occurred: {e}")

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# Delete user and all their data
def delete_user(username, password):
    connection = get_db_connection('passmate')  # Establish database connection
    cursor = connection.cursor()

    try:
        logging.info(f"Attempting to delete user: {username}")
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user[0]):
            logging.info(f"Password verified for user: {username}")
            confirmation = input(f"\nWARNING: You are about to delete the account for '{username}'.\n"
                                 "This action cannot be undone. All data will be permanently deleted.\n"
                                 "Type 'DELETE' to confirm account deletion, or 'CANCEL' to abort: ").strip().upper()

            if confirmation == 'DELETE':
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                cursor.execute(f"DROP TABLE IF EXISTS {username}_passwords")
                connection.commit()
                logging.info(f"Account for user '{username}' deleted successfully.")
                return "Account deleted. Returning to the login menu."
            else:
                logging.info(f"Account deletion for '{username}' canceled.")
                return "\nAccount deletion canceled."
        else:
            logging.warning(f"Password mismatch for user '{username}'. Account deletion aborted.")
            return "Password does not match. Account deletion aborted."

    except sqlite3.Error as e:
        logging.error(f"Database error while deleting user '{username}': {e}")
        return "An error occurred while deleting the account."

    except Exception as e:
        logging.error(f"Unexpected error occurred while deleting user '{username}': {e}")
        return "An unexpected error occurred."

    finally:
        cursor.close()
        connection.close()


def display_logo():
    logo = """
██████╗  █████╗ ███████╗███████╗███╗   ███╗ █████╗ ████████╗███████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
██████╔╝███████║███████╗███████╗██╔████╔██║███████║   ██║   █████╗  
██╔═══╝ ██╔══██║╚════██║╚════██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
██║     ██║  ██║███████║███████║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗

------------# Welcome to the PassMate Password Manager! #------------
    """
    print(logo)


def main():
    while True:
        display_logo()
        print("1. Log into an existing user")
        print("2. Create a new user")
        print("3. Exit the program\n")
        valid, choice = validate_number(input("Select an option (1-3): "), 3)
        if not valid:
            print(choice)
            continue

        if choice == 1:
            username = input("\nEnter your username (or type 'exit' to return to the main menu): ")
            if username.lower() == 'exit':
                print(dupe)
                continue

            valid, username = validate_string(username, "username")
            if not valid:
                print(username)
                continue

            password = masked_input("Enter your password (or type 'exit' to return to the main menu): ")
            if password.lower() == 'exit':
                print(dupe)
                continue

            valid, password = validate_string(password, "password")
            if not valid:
                print(password)
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
                        service = input("Enter the service name (or type 'exit' to return to the main menu): ")
                        if service.lower() == 'exit':
                            print(dupe)
                            break
                        valid, service = validate_string(service, "service")
                        if not valid:
                            print(service)
                            continue

                        service_username = input("Enter the username (or type 'exit' to return to the previous menu): ")
                        if service_username.lower() == 'exit':
                            print(dupe)
                            break
                        valid, service_username = validate_string(service_username, "username")
                        if not valid:
                            print(service_username)
                            continue

                        service_password = masked_input("Enter the password (or type 'exit'"
                                                        "to return to the previous menu): ")
                        if service_password.lower() == 'exit':
                            print(dupe)
                            break
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
                        service = input("Enter the service entry to delete (or type 'exit'"
                                        "to return to the previous menu): ")
                        if service.lower() == 'exit':
                            print(dupe)
                            break
                        valid, service = validate_string(service, "service")
                        if not valid:
                            print(service)
                            continue
                        delete_password(service, password_key)

                    elif choice == 5:
                        result = delete_user(username, password)
                        print(result)
                        if "deleted" in result.lower():
                            print("Logging out and returning to the main menu...")
                            break

                        elif "canceled" in result.lower():
                            print(dupe, "\n")
                            continue

                    elif choice == 6:
                        print("Logging out...")
                        break

            else:
                print("\nAuthentication failed!")

        elif choice == 2:
            while True:
                username = input("Enter a new username (or type 'exit' to return to the main menu): ")
                if username.lower() == 'exit':
                    print(dupe)
                    break
                valid, username = validate_string(username, "username")
                if not valid:
                    print(username)
                    continue

                if not user_exists(username):
                    password = masked_input("Enter a new password (or type 'exit' to return to the main menu): ")
                    if password.lower() == 'exit':
                        print(dupe)
                        break
                    valid, password = validate_string(password, "password")
                    if not valid:
                        print(password)
                        continue

                    if create_new_user(username, password):
                        print(f"New user '{username}' created successfully! You may log in now.")
                        break
                else:
                    print("Username already exists. Please choose a different username.\n")

        elif choice == 3:
            print("Exiting the Password Manager.")
            break

        else:
            print("Invalid option, please try again.")


if __name__ == "__main__":
    get_db_connection('passmate')
    main()
