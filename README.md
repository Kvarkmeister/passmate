# PassMate

> A Secure CLI-based Password Manager for Personal Use

PassMate is designed as a rudimentary proof-of-concept password management ensuring security.

Link to the report:
https://docs.google.com/document/d/1_A1BKry2RI-DzSgCGABnrT3cnROFiwF14vYYrAv3CvA/edit?usp=drivesdk

## Table of Contents

## Features
* **User Authentication**: log-in using BCrypt hashing
* **Password Management**: add, retrieve and delete service credentials using AES ciphers
* **Account Management**: registration and unregistration of user accounts
* **Command Line Interface**: intuitive and beautiful command-line navigation

## Prerequisites
* `os`  
* `bcrypt`  
* `keyboard`  
* `logging`  
* `re`  
* `sqlite3`  
* `sys`  
* `default_backend` from `cryptography.hazmat.backends`
* `Cipher`, `algorithms`, `modes` from `cryptography.hazmat.primitives.ciphers`
* `padding` from `cryptography.hazmat.primitives`
* `Fernet, InvalidToken` from `cryptography.fernet` 

## Installation
1. Ensure Python version 3+ is installed
2. Clone the repository using HTTP
3. *(optional) Open the repository and create a new Virtual Environment*
4. Ensure the dependencies are installed using:

    pip install cryptography
    pip install mysql-connector-python cryptography
    pip install bcrypt
    pip install keyboard

5. Run the script: `python passmate.py`

## Usage Instructions

**Running the Program**
 1. Run the script: `python passmate.py

**Main Menu**

 1. First create an account using option `2`
 2. Log in using option `1`

**User Menu**
 1. Add various passwords using option `1`
 2. Retrive passwords using option `2`
 3. If you forgot what service names You used, option `3` lets you retrieve it
 4. Delete passowrd uisng `4`
 5. Delete the account using `5`
 6. Exit the account using `6`

## Technical Overview
* **User Interaction**: CLI is utilised
* **Database Management**: Each user has a dedicated SQLite database table
* **Encryption**: passwords are encrypted before storage and decrypted during retrieval
* **Logging**: all non-sensitive interactions are logged by the system
* **Error-handling**: the program catches exceptions and returns errors

## Security Considerations
* **Hashing**: BCrypt
* **Encryption**: AES using salt
* **Authentication**: each user uses hashed passwords to log in
* **Secure Database Management**; each user has a separate table; parametrised statements
* **Input validation**: strict rules, sanitisation techniques
* **User awareness**: user consent is required before deleting valuable data
* **Logging**: all non-sensitive interactions are logged by the system
* **Error-handling**: error messages are sanitised
* **Secure UI**: password input is hidden
* **User guidance**: everything about the program is documeneted

## Future Enhancements
* Graphical User Interface
* Ease of use

## Contributions
You may always write to me in case bugs are discovered or there are suggestions for further improving this program.

## License

> No licenses used

## Acknowledgements
Thanks to the following third-parties for creating the possibility for the project:
* **JetBrains** for developing PyCharm
* **Ali Ghasempour** for inspiring the project

# Contact Information
* **Facebook Messenger**: [M.Tammekivi](https://www.facebook.com/M.Tammekivi)
* **GitHub:** Kvarkmeister
* **Discord:** Kvarkmeister
* **Email:** matthiastammekivi@gmail.com
