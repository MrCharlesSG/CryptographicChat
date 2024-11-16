<!-- TOC start (generated with https://github.com/derlin/bitdowntoc) -->

   * [Introduction](#introduction)
      + [Problem to Solve](#problem-to-solve)
         - [Impact on CIANA Pentagon](#impact-on-ciana-pentagon)
      + [User Stories](#user-stories)
   * [Solution](#solution)
      + [System Overview](#system-overview)
      + [User Data in the Database](#user-data-in-the-database)
      + [Chat Representation](#chat-representation)
      + [Key Cryptographic Concepts](#key-cryptographic-concepts)
      + [Secure Communication with the Server](#secure-communication-with-the-server)
      + [Registration Process](#registration-process)
      + [Chat Creation](#chat-creation)
      + [Sending Messages](#sending-messages)
      + [Impact of the Solution on the CIANA Pentagon](#impact-of-the-solution-on-the-ciana-pentagon)
   * [Ciphers](#ciphers)
   * [Risks](#risks)
   * [Future](#future)
   * [Getting Started](#getting-started)
      + [Repository Structure](#repository-structure)

<!-- TOC end -->

<!-- TOC --><a name="cryptographicchat"></a>
# CryptographicChat

<!-- TOC --><a name="introduction"></a>
## Introduction

<!-- TOC --><a name="problem-to-solve"></a>
### Problem to Solve

This project addresses the need for a secure, end-to-end backend system where only users involved in a conversation can access the content of their chats. Neither the server nor potential attackers can decipher the communication. The objective is to uphold the five pillars of CIANA, as defined by NIST: **Confidentiality**, **Integrity**, **Availability**, **Authentication**, and **Non-repudiation**.

The system is designed around three strict requirements:

1. **Exclusive User Access**:
    - Only users involved in a chat can access its content. Users cannot deny their participation in creating chats or sending messages.
        - For example, Bob can access messages exchanged with Alice but cannot view her messages with Carol.
        - The server cannot access or decipher user messages.
2. **Password Efficiency**:
    - Users are required to enter their password only once per session (during registration, the password is confirmed by re-entering it).
3. **Privacy and Security Against Zelda**:
    - If an external actor (Zelda) gains access to the database or intercepts server requests and responses, they must not be able to deduce who is communicating with whom or the content of the conversations. Zelda must also be unable to alter the chat data.

<!-- TOC --><a name="impact-on-ciana-pentagon"></a>
#### Impact on CIANA Pentagon

This design ensures compliance with the CIANA pentagon suggested by NIST as follows:

1. **Confidentiality**: Only the users involved in a chat can view its messages or know their interlocutors.
2. **Integrity**: Messages cannot be tampered with once sent. Any unauthorized changes must be detectable by users.
3. **Availability**: Users can send and receive messages seamlessly, entering their password only once per session.
4. **Authentication**: Only authenticated and registered users can participate in chats.
5. **Non-repudiation**: Users cannot deny sending a message once it has been delivered.

<!-- TOC --><a name="user-stories"></a>
### User Stories

To provide a clear perspective on the system’s functionality, the following user stories have been defined:

1. **Login**: As a user, I want to log in by entering my username and password.
2. **Access Chats**: As a user, I want to access all my previous chats after logging in.
3. **Create New Chats**: As a user, I want to create a new chat with another user.
4. **Send Messages**: As a user, I want to send messages within an existing chat.
5. **Register**: As a user, I want to register by providing my name, setting a provisional password, and receiving my private key.

<!-- TOC --><a name="solution"></a>
## Solution

To grasp the proposed solution, it’s essential to first understand the problem thoroughly. The challenge lies in the fact that an adversary, referred to as Zelda, has access to virtually everything: requests and responses, sockets, and database connections. Despite this, the application needs to function like any conventional system, using familiar concepts like usernames and passwords.

<!-- TOC --><a name="system-overview"></a>
### System Overview

The integration of cryptography into real-world applications is inherently complex. This project addresses the challenge with the following key elements:

1. **Usernames and Passwords as Keys**:
    - Usernames serve as public keys, providing a mapping to users while remaining fully public.
    - Private keys are derived from and stored encrypted with user passwords. Whoever possesses the password has control over the private key.
    - Public usernames should not reveal the user’s real-world identity (e.g., "Joe Smith"), instead using nicknames to maintain anonymity, akin to blockchain principles of **public anonymity**.
2. **Server as a Trusted Authority**:
    - The server also holds a public-private key pair and acts as a trusted authority.
    - Users communicate with the server using a symmetric key, which is encrypted with the server’s public key and stored securely in the database.

![Untitled_Diagram-Problem_Infografia drawio](https://github.com/user-attachments/assets/3cdca05b-3083-41e6-845d-22fce84b63ff)


System Overview

<!-- TOC --><a name="user-data-in-the-database"></a>
### User Data in the Database

For each user, the database contains:

- **Private Key**: Encrypted with the user’s password.
- **Public Key and Username**: Publicly accessible.
- **Symmetric Encryption Key**: Used for server communication, encrypted with the server’s public key.

<!-- TOC --><a name="chat-representation"></a>
### Chat Representation

Chats are represented as follows:

- **Chat ID**: For quick identification.
- **Participants**: Public keys of the two participants, hashed to ensure they can be mapped by the server but not identified by Zelda.
- **Chat Encryption Key**: Used to encrypt messages, stored twice (once for each participant) and encrypted with each participant’s public key.
- **Participant Info**: (username and public key) encrypted with the chat encryption key for additional privacy.

Messages in the database are structured as:

- **Unique Message ID**
- **Message Info**: Includes the sender’s username, timestamp, and text, encrypted with the chat encryption key.
- **Signature**: The message info, signed by the sender’s private key. This ensures the integrity of the message and verifies its origin.

<!-- TOC --><a name="key-cryptographic-concepts"></a>
### Key Cryptographic Concepts

- **Asymmetric Encryption**: Data encrypted with a public key can only be decrypted by the corresponding private key (and vice versa).
- **Digital Signature**: A message is hashed and encrypted with the sender's private key. Anyone with the public key can verify it, but only the sender could create it.

<!-- TOC --><a name="secure-communication-with-the-server"></a>
### Secure Communication with the Server

When a user logs in, the server provides a **digital envelope** containing all necessary credentials and data. This envelope includes:

- Encrypted private key (using the user’s password).
- Symmetric encryption key (encrypted with the user’s public key).
- Public key and username (encrypted with the symmetric key).
- Signature of the private key, done by the server.
- Chat data, including:
    - Chat ID (encrypted with the symmetric key).
    - Chat encryption key (encrypted with the user’s public key).
    - Participant info (encrypted with the chat encryption key).
    - Messages, including encrypted message info and signatures.

The user decrypts this information locally using their password, and checking out that the signature is correct.

<!-- TOC --><a name="registration-process"></a>
### Registration Process

During registration, the user sets a username and password. The server generates the required keys, encrypts them appropriately, and sends them to the user. The user confirms the password to decrypt the received data and complete the setup.

<!-- TOC --><a name="chat-creation"></a>
### Chat Creation

To create a chat, the initiating user sends:

- Their username, encrypted with the server’s public key.
- The recipient’s username, encrypted with the symmetric key.

The server decrypts this data, generates a unique chat ID and a chat encryption key, and stores them as outlined earlier. It then sends the chat information back to both users, ensuring only the participants can access it.

<!-- TOC --><a name="sending-messages"></a>
### Sending Messages

When sending a message, the user provides the following to the server:

1. **Header**: The sender’s username, encrypted with the server’s public key.
2. **Chat Metadata**: Includes the recipient’s username and chat ID, encrypted with the symmetric key.
3. **Message**: The content (timestamp, sender’s username, and text) encrypted with the chat encryption key.
4. **Signature**: The signed message info, ensuring authenticity and integrity.

The server processes the header and metadata to identify the sender and recipient but cannot decrypt the message itself. It stores the message and sends it to the recipient (if connected), including the signature for verification.

<!-- TOC --><a name="impact-of-the-solution-on-the-ciana-pentagon"></a>
### Impact of the Solution on the CIANA Pentagon

1. **Confidentiality.** User messages are encrypted using a unique **chat encryption key**, which is only accessible to the participants. This means only they can decrypt and read the messages. Neither the server nor unauthorized users (including attackers) can access the content.
2. **Integrity.** Messages are signed with the sender’s private key, and the recipient can verify these signatures using the sender's public key. This guarantees that the message originates from the claimed sender and that it has not been altered. If any changes are made to a message after it has been sent, the signature verification will fail, alerting the recipient of tampering.
3. **Availability.** Users only need to enter their password once per session, simplifying access without compromising security. Encryption and decryption processes are handled efficiently to minimize any impact on performance, ensuring prompt access to messages.
4. **Authentication.** Each user has a unique public-private key pair and a encryption, and only registered users with a valid password can retrieve and use their private key. The server issues signed digital envelopes to authenticate users at the start of each session. These contain encrypted user credentials and session keys, further ensuring that only legitimate users can participate.
5. **Non-repudiation.** Messages are signed using the sender’s private key, which binds the sender to the message. Since only the sender holds the private key, they cannot deny having sent the message once it is signed and received by the other participant. 

<!-- TOC --><a name="ciphers"></a>
## Ciphers

The ciphers user are:

- AES (Advanced Encryption Standard) with CBC Mode
    - Used for symmetric encryption
    - Operates Cipher Block Chaining (CBC) mode, which adds randomness by using an Initialization Vector (IV) to ensure that identical plaintext blocks result in different ciphertexts.
    - The symmetric keys are derived using **SHA-256**, providing strong cryptographic strength for key generation.
- RSA (Rivest-Shamir-Adleman)
    - Used for asymmetric encryption and signing.
    - Utilizes the **PKCS#1 OAEP** padding scheme, which enhances security by incorporating randomization during encryption, preventing predictable ciphertext.
- PBKDF2
    - Used for the derivation of cryptographic hashes for participant data, such as generating unique identifiers (hashes) for users in chats.
    - Combines HMAC (Hash-based Message Authentication Code) with **SHA-256** for secure hash computation.

<!-- TOC --><a name="risks"></a>
## Risks

1. **Compromise of User Password**
    - **Description**: if a user's password is weak or predictable, an attacker (Zelda) could use brute force or other password-guessing techniques to decrypt the user's private key. This would grant Zelda access to the user's chats, including messages and potentially the identity of chat participants.
    - **Impact**: loss of confidentiality for the affected user's messages and chats. Leakage of all conversations and other users identity.
    - **Mitigation**: enforce strong password policies (minimum length, complexity requirements). Educate users that have to trust with whom they are talking with.
2. **Traffic Analysis by Zelda**
    - **Description**: even though message content is encrypted, Zelda could monitor network traffic to observe patterns such as who is communicating with whom (e.g., Alice and Bob) based on metadata. While the system hides real-world identities, this traffic analysis could reveal communication relationships.
    - **Impact**: partial compromise of user anonymity.
    - **Mitigation**: maintaining users real-world anonymity
3. **Leakage of server private key**
    1. **Description**:  If the server mishandles the encryption keys the entire system's security could be compromised.
    2. **Impact**: breach of confidentiality and integrity of all the system’s communication and storage.
    3. **Mitigation**: store server keys securely and rotation policies for encryption keys.
4. **Loss of Anonymity**
    - **Description**: over time, Zelda could correlate (somehow but not with system information) the username with the real-world-person
    - **Impact**: reduced user anonymity and privacy. Zelda can now if user is talking with other no-anonymous users but can’t see the content.
    - **Mitigation**: allow users to generate a new identity
5. **Phishing Attacks on Users**
    - **Description**: An attacker could trick users into divulging their passwords or private keys via social engineering techniques.
    - **Impact**: Compromise of user accounts and potential exposure of sensitive data.
    - **Mitigation**: Educate users on recognizing phishing attempts.
6. **Phishing attacks inside system**
    - **Description**: a user (e.g., Alice) could mistakenly start a conversation with an impersonator (e.g., Eve, pretending to be Eve33). This could result in the unintentional disclosure of sensitive information to the wrong participant.
    - **Impact**: leakage of sensitive information to malicious users.
    - **Mitigation**: educate users to carefully verify the recipient's identity before sharing sensitive information. Implement clear user verification tools or visual indicators within the system to help distinguish between users with similar usernames. Permit users to report this kind of users and black-listing of users

<!-- TOC --><a name="future"></a>
## Future

While there are currently no specific plans for future changes, the system could evolve to include features and improvements that enhance usability, security, and scalability. Below are some potential ideas:

- Enable users to generate new identities within the system to maintain anonymity and avoid potential correlation of activities over time.
- Implement a secure method for users to recover their accounts if they forget their passwords.
- Allow users to permanently delete their accounts and associated data from the system.
- Introduce a mechanism for users to report abusive or inappropriate behavior.
- Audit logs and transparency tools

<!-- TOC --><a name="getting-started"></a>
## Getting Started

- To run a client instance  `/client/client-app.py`.
- To run a server instance `/server/server-app.py`

<!-- TOC --><a name="repository-structure"></a>
### Repository Structure

- `cipher`: has all the ciphers used in the project. All cipher for encryption and decryption gets an string and return string, so its more abstract.
- `utils`: has only one class `StringUtils` used to concatenate and decatenate different structures such as the chat metadata, message information and so on.
- `client`: has everything the clients need to run
    - `model` stores the `DecryptedChat` that decrypt an incoming chat so it is easier for the frontend to represent and centralize the decryption.
    - `service` used to send and receive the encrypted information. There are two `AuthService` and `ChatService` used for different purposes.
    - `templates` stores the html views
    - `client-app.py` used to run a client instance, have the routes of the frontend, the Rest API endpoints and the socket listener.
- `server`: has everything the server needs to run
    - `config` stores the configuration of the database (by the moment is dummy and is a JSON)
    - `dal` access the database we have the `UserRepository`,`ChatRepository`, and `MessageRepository`.
    - `model` encrypt plain information and represent the `Message`,`Chat` and `User`.
    - `service` receive the information, makes it make sense and return it. Have the same service of the client: `AuthService` and `ChatService`.
    - `server-app.py` used to run a server instance, have the REST API endpoints of the and emit and listen the socker connections.
