<!-- TOC start (generated with https://github.com/derlin/bitdowntoc) -->

- [Introduction](#introduction)
   * [The CIA Triad](#the-cia-triad)
   * [Terminology](#terminology)
      + [Threat Consequences](#threat-consequences)
      + [Examples of Threats](#examples-of-threats)
   * [Security Implementation](#security-implementation)
   * [CIANA](#ciana)
- [Block Ciphers](#block-ciphers)
   * [Effects of Modifying a Ciphertext Block](#effects-of-modifying-a-ciphertext-block)
- [SSL and Symmetric Encryption](#ssl-and-symmetric-encryption)
   * [SSL](#ssl)
   * [Symmetric Encryption](#symmetric-encryption)
      + [Types](#types)
      + [Requirements for the Secret Key](#requirements-for-the-secret-key)
      + [Symmetric Ciphers](#symmetric-ciphers)
      + [OTP](#otp)
      + [What makes a good cipher?](#what-makes-a-good-cipher)
   * [Stream Cipher](#stream-cipher)
   * [LAB: Encrypt and Decrypt using AES and CBC](#lab-encrypt-and-decrypt-using-aes-and-cbc)
   * [Symmetric Encryption Algorithms](#symmetric-encryption-algorithms)
      + [DES (Data Encryption Standard)](#des-data-encryption-standard)
      + [Triple DES](#triple-des)
      + [AES (Advance Encryption Standard)](#aes-advance-encryption-standard)
- [Integrity Preservation](#integrity-preservation)
   * [When Integrity is the Sole Concern](#when-integrity-is-the-sole-concern)
      + [MAC (Message Authentication Code)](#mac-message-authentication-code)
   * [Hash Functions](#hash-functions)
      + [Characteristics of Hash Functions](#characteristics-of-hash-functions)
      + [Hash Functions in Practice](#hash-functions-in-practice)
      + [Example of Hashing a Message in Code](#example-of-hashing-a-message-in-code)
   * [LAB: Integrity Message](#lab-integrity-message)
- [Symmetric vs. Asymmetric Encryption](#symmetric-vs-asymmetric-encryption)
   * [Symmetric Encryption](#symmetric-encryption-1)
   * [Asymmetric Encryption (Public-Key Cryptography)](#asymmetric-encryption-public-key-cryptography)
   * [Digital Envelopes](#digital-envelopes)
   * [Public Key Infrastructure (PKI) and Certificate Authorities (CAs)](#public-key-infrastructure-pki-and-certificate-authorities-cas)
      + [What is PKI?](#what-is-pki)
      + [Key Components of PKI:](#key-components-of-pki)
      + [How PKI Works with Certificate Authorities:](#how-pki-works-with-certificate-authorities)
      + [Example](#example)
      + [Benefits of PKI and CAs:](#benefits-of-pki-and-cas)
- [RSA (Rivest, Shamir, Adleman)](#rsa-rivest-shamir-adleman)

<!-- TOC end -->

<!-- TOC --><a name="cryptography"></a>
# Cryptography

<!-- TOC --><a name="introduction"></a>
# Introduction

Computer Security is defined by the NIST as the protection afforded to an automated information system in order to attain the applicable objectives of preserving the integrity, availability and confidentiality of information system resources

<!-- TOC --><a name="the-cia-triad"></a>
## The CIA Triad

1. Confidentiality → permissions, only the people that is allow to see the data can actually see the data
2. Integrity → data is not being alter in anyway is not intended
3. Availability → ensuring timely and reliable access to and use of information

At the end we want to follow the key atributes of CIANA:

1. CIA triad
2. Non-repudiation → a user cannot deny (repudiate) having performed a transaction
3. Authentication

<!-- TOC --><a name="terminology"></a>
## Terminology

- **Adversary (thread agent)** → an entity that attacks, or is a thread to, a system.
- **Attack** → an assault on system security that derives from an intelligent threat; that is, an intelligent act that is a deliberate attempt (especially in the sense of the method or technique) to evade security services and violate the security policy of a system.
    - passive → does not affect system resources
    - active → attempt to alter system resources or affect their operation
    - insider → initiated by an entity inside the security parameter
    - outsider → initiated from outside the perimeter
- **Countermeasure** → an action, device, procedure, or technique that reduces a threat, a vulnerability, or an attack by eliminating or preventing it, by minimizing the harm it can cause, or by discovering and reporting it so that corrective action can be taken.
- **Risk** → an expectation of loss expressed as the probability that a particular threat will exploit a particular vulnerability with a particular harmful result
- **Security Policy** → a set of rules and practices that specify or regulate how a system or organization provides security services to protect sensitive and critical system resources.
- **System Resource (Asset)** → data contained in an information system; or a service provided by a system; or a system capability; or an item of system equipment; or a facility that houses system operations and equipment.
- **Threat** → a potential for violation or security, which exists when there is a circumstance, capability, action, or event that could breach security and cause harm. That is, a threat is a possible danger that might exploit a vulnerability.
- **Vulnerability** → a flaw or weakness in a system’s design, implementation, or operation and management that could be exploited to violate the system’s security policy. The categories are:
    - corrupted (loss of integrity)
    - leaky (loss of confidentiality)
    - unavailable of very slow (loss of availability)

![image](https://github.com/user-attachments/assets/526e6cf3-70c4-4845-ad2e-d86bc4b404b1)


<!-- TOC --><a name="threat-consequences"></a>
### Threat Consequences

| **Threat Consequence** | **Threat Action (attack)** |
| --- | --- |
| Unauthorized Disclosure→ A circumstance or
event whereby an entity
gains access to data for
which the entity is not
authorized.

 | Exposure → Sensitive data are directly released to an unauthorized entity.
Interception → An unauthorized entity directly accesses sensitive data traveling between authorized sources and destinations.
Inference → A threat action whereby an unauthorized entity indirectly accesses sensitive data (but not necessarily the data contained in the communication) by reasoning from characteristics or byproducts of communications.
Intrusion → An unauthorized entity gains access to sensitive data by circumventing a system's security protections. |
| Deception → A circumstance or event that may  result in an authorized entity receiving false data and
believing it to be true.
 | Masquerade → An unauthorized entity gains access to a system or performs a malicious act by posing as an authorized entity.
Falsification → False data deceive an authorized entity.
Repudiation → An entity deceives another by falsely denying responsibility for an act. |
| Disruption → A circumstance or event that interrupts or prevents the correct operation of system services and functions.
 | Incapacitation → Prevents or interrupts system operation by disabling a system component.
Corruption → Undesirably alters system operation by adversely modifying system functions or data.
Obstruction → A threat action that interrupts delivery of system services by hindering system operation. |
| Usurpation → A circumstance or event that results in
control of system services or functions by an unauthorized entity. | Misappropriation → An entity assumes unauthorized logical or physical control of a system resource.
Misuse → Causes a system component to perform a function or service that is detrimental to system security. |

<!-- TOC --><a name="examples-of-threats"></a>
### Examples of Threats

|  | Availability | Confidentiality | Integrity |
| --- | --- | --- | --- |
| Hardware | Equipment is stolen or
Hardware disabled, thus denying service. |  |  |
| Software | Programs are deleted,
denying access to users. | An unauthorized copy
of software is made. | A working program is
modified, either to
cause it to fail during
execution or to cause it
to do some unintended
task. |
| Data | Files are deleted,
denying access to users. | An unauthorized read of data is performed.
An analysis of
statistical data reveals
underlying data. | Existing files are
modified or new files
are fabricated. |
| Communication Lines | Messages are destroyed
or deleted.
Communication lines
or networks are
rendered unavailable. | Messages are read. The delayed, reordered, or
traffic pattern of
messages is observed. | Messages are modified,
duplicated. False
messages are
fabricated. |

<!-- TOC --><a name="security-implementation"></a>
## Security Implementation

Involves four complementary courses of actions:

- **Detection**
    - intrusion detection systems
    - detection of denial of service attacks
- **Recove**
    - Use of backup systems
- **Response**
    - Upon detection → being able to halt an attack and prevent further damage
- **Prevention**
    - Secure encryption algorithms
    - Prevent unauthorized access to encryption keys

<!-- TOC --><a name="ciana"></a>
## CIANA

IA (Information Assurance) is the practice of managing risks while maintaining CIANA properties

1. **Confidentiality** → assurance that information is not disclosed to unauthorized individuals, processes, or devices
    - **Example 1**: An employee at a bank accesses a celebrity client’s account without authorization to view transaction history and then shares the information with friends. This violates confidentiality as unauthorized individuals gained access to sensitive data.
    - **Example 2**: A hacker intercepts confidential data during a file transfer between two servers, obtaining information meant to remain private, such as credit card details or login credentials.
2. **Integrity** → means no unauthorized modification or destruction of information. 
    - **Example 1**: An attacker gains access to a company’s database and changes order information, altering quantities and prices. This compromises the integrity of the information since the modified data no longer reflects accurate records.
    - **Example 2**: A malware infection modifies the content of financial reports before they are sent to clients, leading to inaccurate reporting and causing potential legal and financial issues due to incorrect data.
3. **Availability  →** timely, reliable access to data and information services for authorized users.
    - **Example 1**: A distributed denial-of-service (DDoS) attack overwhelms a company’s website, making it inaccessible to legitimate users. This is a violation of availability as it prevents authorized users from accessing the service when needed.
    - **Example 2**: A ransomware attack locks critical data and systems in a hospital, preventing doctors and nurses from accessing patient records, which delays or disrupts patient care.
4. **Non-repudiation** → assurance the sender of the data is provided with proof of delivery and the recipient is provided with proof of the sender’s identity, so neither can later deny having processed the data.
    - **Example 1**: An e-commerce platform fails to provide digital receipts after online purchases. As a result, customers and the company could later dispute whether a transaction occurred, violating non-repudiation.
    - **Example 2**: An email spoofing attack allows an attacker to send messages appearing to be from a legitimate user, allowing the sender to deny they sent it if issues arise. This makes it difficult to hold the actual user accountable, impacting non-repudiation.
5. **Authentication** → security measure designed to establish the validity of a transmission, message or originator, or a means of verifying an individual’s authorization  to receive specific categories of information
    - **Example 1**: A social media platform has weak authentication protocols, allowing attackers to easily guess or brute-force user passwords and gain unauthorized access to accounts. This failure compromises authentication as it doesn’t validate user identity adequately.
    - **Example 2**: A company’s internal system doesn’t verify users with multi-factor authentication (MFA), allowing anyone with a password to access sensitive data. This weakens authentication since it lacks a robust verification process, making it easier for unauthorized users to gain access.

<aside>

Understanding something as an attack requires understanding which of the pillars has being violated.

</aside>

<!-- TOC --><a name="block-ciphers"></a>
# Block Ciphers

Block ciphers work by dividing data—whether it’s a document, file, or message—into fixed-size blocks and then encrypting each block individually. Different block cipher operation modes (or *chaining modes*) define how blocks are processed and linked to enhance security:

1. Electronic code book (ECB) → the plaintext is divided into blocks, and each is XORed with the key.
2. Cipher block chaining (CBC) → plain text is split into blocks. Each block is XORed with previous block  and the key to get the cipher text block. 
    1. So having m1…mm blocks that leads to c1…cm encryptions.  We say that `ci = mi XOR ci-1 XOR key`
    2. For the c0 we use the *initialization vector* (IV). A block of bits that are user to randomize the encryption and hence to produce distinct cipher texts.
3. Cipher Feedback (CFB) → similar to CBC but different algorithm for encryption.
4. Output Feedback (OFB) → operates as a stream cipher, transforming block ciphers into a stream cipher approach.

<aside>


The **randomness of the key** is essential in all block cipher modes. Since the encryption algorithm uses this key to control the transformation of data, the strength of encryption ultimately depends on keeping the key both random and secret. A strong, unpredictable key disrupts any attempts to deduce patterns or recover the original message, effectively making this randomness the core of encryption strength.

</aside>

<!-- TOC --><a name="effects-of-modifying-a-ciphertext-block"></a>
## Effects of Modifying a Ciphertext Block

Let’s examine the outcome of flipping a single bit in the second ciphertext block in both ECB and CBC modes:

1. **Get the original plaintext**
2. **Encrypt it using the chosen mode**
3. **Flip one bit of the second ciphertext block**
4. **Decrypt the modified ciphertext**
5. **Observe the resulting plaintext**

**Solution**

- **In ECB mode** → Only the second plaintext block will contain an error. Since ECB processes blocks independently, the modification in the second ciphertext block only affects its corresponding plaintext block. The rest of the plaintext remains intact.
- **In CBC mode** → Both the second and third plaintext blocks will contain errors. Since CBC mode relies on the previous block's ciphertext for decryption, modifying the second ciphertext block disrupts the decryption of the second block and propagates errors into the third block. The remaining blocks beyond the third will decrypt correctly.

<!-- TOC --><a name="ssl-and-symmetric-encryption"></a>
# SSL and Symmetric Encryption

<!-- TOC --><a name="ssl"></a>
## SSL

Secure Socket Layer is the framework to secure, for instance, web traffic. Uses different methods of encryption to achieve specific goals. 

Our main goals will be:

1. **No eavesdropping** → network layer attack that focuses on capturing small network packets transmitted by other computers and reading the data content in search of any type of information. (**Confidentiality**)
2. **No tampering** → consist of modifying the parameters that are sent to the web server as entry points of the application, whether those that travel in the forms or in the URL itself. (**Integrity**)

SSL involves two primary protocols to secure communications:

1. **Handshake protocol →** establish a shared secret.
2. **Send data →** send data using the shared secret.

<!-- TOC --><a name="symmetric-encryption"></a>
## Symmetric Encryption

Symmetric encryption is an essential component of SSL, used to secure data after the handshake. In symmetric encryption, both parties use the same secret key for encryption and decryption, making it efficient for rapid data transfer.

Imaging we have Alice and Bob. Alice has the encryption machine and Bob has the decryption machine. Alice want to send a message to Bob, she will do `E(k, m) = c` and bob will get c and do `D(k, c) = m` . Both need the shame `k` to communicate. 

<!-- TOC --><a name="types"></a>
### Types

- Block Cipher
- Stream Cipher

<!-- TOC --><a name="requirements-for-the-secret-key"></a>
### Requirements for the Secret Key

The key used in symmetric encryption must fulfill two criteria:

1. **Sufficiently Large** - A typical size, like 128 bits, provides a good balance between security and performance.
2. **Randomness** - The key should be as unpredictable as possible to ensure robust encryption.

The challenge is how do we exchange the key?

<aside>


The encryption algorithms are publicly known. So is the key (`k`) the one that need to be secret

</aside>

> The core of cryptography is:
      1. Secret key establishment
      2. Secure communication with stablished key
> 

<!-- TOC --><a name="symmetric-ciphers"></a>
### Symmetric Ciphers

A cipher is defined as a pair of efficient algorithms (E, D), where: 

- `E(k, m) => c` and
- `D(k, c) => m`
- given the *consistency equation* `D(k, E(k, m)) => m`
- `E -> k XOR m`
- `D -> k XOR c`

<aside>


At the end we use DES, 3DES and AES operation instead of XOR that are a more complex version of XOR.

</aside>

<!-- TOC --><a name="otp"></a>
### OTP

The **One-Time Pad (OTP)** is an encryption technique where the key is as long as the message itself, providing theoretically perfect security if the key is truly random and used only once. However:

- If a large message is divided into blocks and encrypted with the same key, predictable patterns can emerge in the ciphertext, revealing information about the plaintext.
- OTP is impractical for large messages since generating and securely sharing enormous keys is challenging.

<!-- TOC --><a name="what-makes-a-good-cipher"></a>
### What makes a good cipher?

A good cipher should meet the following criteria:

1. **Ciphertext Conceals Plaintext**
    - The ciphertext should reveal no information about the plaintext. Even if the same plaintext is encrypted multiple times, each ciphertext should appear completely random and unique.
2. **Cipher Security Property**
    - A cipher is exceptionally secure if, given any two plaintext messages m0 and m1, the probability that they encrypt to the same ciphertext c ⇒ `P[E(k, m0)= c] = P[E(K, mi)=c]`

This means that given the cipher text, you cannot tell if the msg is m0 or mi for a given `c` without knowing the `k`. 

<!-- TOC --><a name="stream-cipher"></a>
## Stream Cipher

Pseudo random number is a number of size `n` generated by an algorithm that is meant to be as random as possible. The idea in the stream cipher is to replace the totally random key from the OTP with a pseudo random key.

PRG ⇒ pseudo random generator, takes a seed so that the function maps the seed string to a much larger key.

In the Stream Cipher each bit of the text is encrypted at a time with the corresponding digit of the key.

<!-- TOC --><a name="lab-encrypt-and-decrypt-using-aes-and-cbc"></a>
## LAB: Encrypt and Decrypt using AES and CBC

In this lab we will do AES as it would be XOR. The lab consist in encrypt and decrypt an image with CBC.
The  [How to Encrypt an Image in Python using AES Algorithm](https://pyseek.com/2024/05/encrypt-an-image-in-python-using-aes-algorithm/) page suggest to have an iv hashed with a nonce, to complex for now. Use random iv.

- Solution
    
    ```python
    import io
    
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    from PIL import Image
    
    class AESCipher:
        def __init__(self, key):
            self.key = bytes(key, encoding="utf-8")
    
        def encrypt_image(self, input_image_path, output_image_path):
            # Load the image
            image = Image.open(input_image_path)
            # Generate a random IV
            iv = get_random_bytes(AES.block_size)
    
            # Convert the image to bytes
            img_byte_array = io.BytesIO()
            image.save(img_byte_array, format=image.format)
            img_bytes = img_byte_array.getvalue()
    
            # Initialize AES cipher
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
    
            # Encrypt the image data with padding
            padded_data = pad(img_bytes, AES.block_size)
            encrypted_data = iv + cipher.encrypt(padded_data)
    
            # Write the encrypted data to the output image file
            with open(output_image_path, 'wb') as f:
                f.write(encrypted_data)
    
            print(f"Encryption successful. Encrypted image saved to '{output_image_path}'.")
    
        def decrypt_image(self, input_image_path, output_image_path):
            # Read the encrypted data
            with open(input_image_path, 'rb') as f:
                encrypted_data = f.read()
    
            # Separate the IV from the encrypted data
            iv = encrypted_data[:AES.block_size]
            encrypted_data = encrypted_data[AES.block_size:]
    
            # Initialize AES cipher
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
    
            # Decrypt the image data
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
            # Convert decrypted bytes to image
            decrypted_image = Image.open(io.BytesIO(decrypted_data))
    
            # Save the decrypted image
            decrypted_image.save(output_image_path, format=decrypted_image.format)
            print(f"Decryption successful. Decrypted image saved to '{output_image_path}'.")
    
    if __name__ == "__main__":
        input_image_path = 'img.png'
        encrypted_image_path = "encrypted_image.png"
        decrypted_image_path = 'decrypted_image.png'
        key = 'ShouldBeARandomKeyWithEightTeenB'
    
        aes_cipher = AESCipher(key)
    
        aes_cipher.encrypt_image(input_image_path, encrypted_image_path)
        aes_cipher.decrypt_image(encrypted_image_path, decrypted_image_path)
    ```
    

<!-- TOC --><a name="symmetric-encryption-algorithms"></a>
## Symmetric Encryption Algorithms

|  | DES (Data Encryption Standard) | Triple DES | AES (Advance Encryption Standard) |
| --- | --- | --- | --- |
| Plaintext block size (bits) | 64 | 64 | 128 |
| Ciphertext block size (bits) | 64 | 64 | 128 |
| Key size (bits) | 56 | 122 or 168 | 128, 192 or 246 |

<!-- TOC --><a name="des-data-encryption-standard"></a>
### DES (Data Encryption Standard)

- The most widely used encryption scheme
- strength concerns
    - DES es the most studied encryption algorithm in existence
    - use of 56-bit key → Electronic Frontier Foundation (EFF) announced in July 1998 that it had broken a DES encryption

<!-- TOC --><a name="triple-des"></a>
### Triple DES

- repeats basic DES algorithm three times using either two or three unique keys
- first standarized for use in financial applications
- attractions:
    - 168-bit key lenght overcomes the vulnerability to brute-force attack of DES
    - underlying encryption algorithm is the same as in DES
- drawbacks:
    - algorithm slow down the software

<!-- TOC --><a name="aes-advance-encryption-standard"></a>
### AES (Advance Encryption Standard)

- 3DES needed a replacement since was not reasonable for long term use
- NIST called for proposal for new AES in 1997
    - should have a security strength better than 3DES
    - significantly improved efficiency
    - symmetric block cipher
    - 128 bits data and 128/192/256 bit keys
- Selected Rijndael in November 2001
- Has been updating over time.

<!-- TOC --><a name="integrity-preservation"></a>
# Integrity Preservation

While **symmetric encryption** is primarily focused on preserving **confidentiality** by ensuring only authorized parties can read the data, **integrity** is addressed through hashing and message authentication codes (MACs). Integrity in cryptography ensures that data has not been altered or tampered with during transmission or storage.

<!-- TOC --><a name="when-integrity-is-the-sole-concern"></a>
## When Integrity is the Sole Concern

In certain cases, the confidentiality of data is not a concern—only the integrity of the message is. Examples include publicly accessible content, such as:

- Code repositories (e.g., GitHub) where the source code should remain unchanged.
- Public videos on platforms like YouTube, where the content is publicly accessible but should not be modified.

In such cases, instead of encrypting the data, we use integrity-preserving methods, such as hashing, to verify that the data remains unaltered.

<!-- TOC --><a name="mac-message-authentication-code"></a>
### MAC (Message Authentication Code)

A **Message Authentication Code (MAC)** provides a way to check the integrity and authenticity of a message. A MAC is a tag attached to a message to confirm that it has not been tampered with and originates from an authentic source.

For example, if Alice wants to send a message mmm to Bob and ensure its integrity, she would generate a MAC for the message using a shared secret key: `S(k, m) => tag`. 

This tag accompanies the message so that Bob, upon receiving message and the MAC, can verify whether the message remains unchanged by recalculating the MAC and comparing it to the received tag.

<!-- TOC --><a name="hash-functions"></a>
## Hash Functions

A **hash function** is a fundamental cryptographic algorithm that maps data of arbitrary length (e.g., a file or a message) to a fixed-length, unique output. This output, known as a **hash** or **digest**, serves as a fingerprint for the original data.

<!-- TOC --><a name="characteristics-of-hash-functions"></a>
### Characteristics of Hash Functions

1. **Fixed-Length Output**: Regardless of the input size, a hash function produces a fixed-length output. For instance, the SHA-256 hash function always generates a 256-bit hash.
2. **Deterministic**: The same input will always produce the same hash.
3. **Pre-image Resistance**: Given a hash, it should be computationally challenging to determine the original message.
4. **Collision Resistance**: It should be infeasible for two different inputs to produce the same hash.
5. **Avalanche Effect**: A small change in the input (e.g., flipping a single bit) should result in a completely different hash.

Hash functions are also used for applications like detecting malware. For instance, antivirus software may use a list of hashes corresponding to known malware signatures. However, viruses can evade detection by altering a single bit in the code, resulting in a completely new hash that avoids blacklist detection.

<!-- TOC --><a name="hash-functions-in-practice"></a>
### Hash Functions in Practice

To understand how a hash function works, let’s break down the steps:

1. **Algorithm Selection**: Choose a hash algorithm (e.g., SHA-256, MD5) to calculate the hash code.
2. **Message Segmentation**: The message is split into fixed-size blocks (e.g., 512 bits in SHA-256). If the final block is smaller than the required size, padding is added. For example, for a 5-bit message split into 2-bit blocks, one bit of padding would be added to create three blocks of 2 bits each.
3. **Iterative Processing**: The hash function processes each block in sequence, applying a series of transformations.
4. **Hash Output**: For an n-bit block size, the hash function ultimately produces an n-bit digest.

<!-- TOC --><a name="example-of-hashing-a-message-in-code"></a>
### Example of Hashing a Message in Code

The following is a simplified example of a hash function’s implementation in pseudocode:

```python
# Initialize a temporary block with a key or initial value
temp_block = key

# Split the message into blocks, adding padding if necessary
list_of_blocks = split(message, n_bits_block_size, padding=True)

# Process each block
for block in list_of_blocks:
    # Apply a hash algorithm (e.g., XOR, SHA)
    temp_block = hash_algorithm(block, temp_block)

# Return the final hash as the output
return temp_block
```

The choice of hash algorithm balances **security** (e.g., resistance to collisions) and **performance** (e.g., processing speed). Algorithms like SHA-256 are commonly used in secure applications due to their robustness and efficiency.

<!-- TOC --><a name="lab-integrity-message"></a>
## LAB: Integrity Message

The lab simulate the sending of a message. The message should be send with a mac, with the probability of 50% modify the message or not, and receive the message and verify its integrity

- Solution
    
    ```python
    import os
    import random
    from Crypto.Hash import HMAC, SHA256
    
    class MessageAuthenticationCode:
        def __init__(self, key):
            self.key = bytes(key, encoding="utf-8")
    
        def send_message(self, input_text_path, destination_path):
            # Read the message from the input file
            with open(input_text_path, 'r') as message_file:
                message = message_file.read()
    
            # Generate HMAC of the message
            hmac_obj = HMAC.new(self.key, message.encode('utf-8'), SHA256)
            message_mac = hmac_obj.hexdigest()
    
            # Combine message and HMAC in the same string
            message_with_mac = message + message_mac
    
            # Write the combined message and HMAC to the destination file
            with open(destination_path, "w") as destination_file:
                destination_file.write(message_with_mac)
    
            print("Message sent correctly.")
    
        def receive_message(self, destination_path):
            # Read the combined message and HMAC from the file
            with open(destination_path, 'r') as destination_file:
                content = destination_file.read()
    
            # Separate the message and the HMAC
            message = content[:-64]
            received_mac = content[-64:]
    
            # Verify the MAC
            hmac_obj = HMAC.new(self.key, message.encode('utf-8'), SHA256)
            try:
                hmac_obj.hexverify(received_mac)
                print("Message integrity verified. Message has not been altered. Here is the message: ", message)
                return True
            except ValueError:
                print("Message integrity verification failed! Message may have been altered.")
                return False
    
    if __name__ == "__main__":
        input_text_path = 'text/text.txt'
        destination_path = "text/message_received.txt"
        key = 'ShouldBeARandomKeyWithEightTeenB'
        message_authentication_code = MessageAuthenticationCode(key)
    
        message_authentication_code.send_message(input_text_path, destination_path)
    
        # Decide randomly whether to modify the file after sending
        modify_message = random.randint(0, 1) == 0
        if modify_message:
            with open(destination_path, "a") as destination_file:
                destination_file.write("\nThis message has been altered.")
    
            print("The message was modified after sending.")
    
        message_authentication_code.receive_message(destination_path)
    
    ```
    

<!-- TOC --><a name="symmetric-vs-asymmetric-encryption"></a>
# Symmetric vs. Asymmetric Encryption

Type of encryption that uses 2 keys. *Symmetric* encryption covers *confidentiality* and  *integrity.* On the other side *asymmetric encryption* covers authentication and non-repudiation.

<!-- TOC --><a name="symmetric-encryption-1"></a>
## Symmetric Encryption

In *symmetric*  encryption we have the following pros and cons (Zelda is the attacker and Bob and Alice the ones that want to share data):

- Pros
    - Confidentiality ⇒ Zelda cannot access the `message` without knowing the key
    - *Authentication* ⇒ only who ever knows the `key` can participate in the communication. This does not mean that who ever  have the `key` is the right party.
    - Integrity ⇒ if the message C is modified it will decrypt to gibberish (make no sense)
- Cons
    - Key distribution is critical and requires out-of-band communication.
    - If key is compromised Zelda can impersonate both Alice and Bob.
    - Cannot be used to prove that the message was sent by specifically one of the involved parties.

> The fundamental limitation of symmetric (secret key) encryption is… how do two parties agree on the key?
> 

<!-- TOC --><a name="asymmetric-encryption-public-key-cryptography"></a>
## Asymmetric Encryption (Public-Key Cryptography)

In ***symmetric (public key) cryptography***, both communicating parties have two keys of their own. 

- Own public key, shared with the world
- Own private key keep as a closely guarded secret

The magic of public cryptography is that a message encrypted with the public key can only be decrypted with the private key.

<aside>


If you encrypt something with private key, can be decrypted with the public key

</aside>

![image 1](https://github.com/user-attachments/assets/b4910f24-02bb-4ab7-9954-661271e6b4a1)


Diagram of how symmetric (public key) cryptography.

Bob can decrypt any message that is encrypted with his public key, but…. How can Bob be sure that the message can from? → if Alice encrypt the message with private key, Bob can decrypted with her public key, but Bob would know that she is actually Alice → we achieve authentication sacrificing *confidentiality*. 

**Example Use of Asymmetric Encryption to Achieve Both Confidentiality and Authentication**:

1. **Sending a Secure Message**:
    - Alice first encrypts her message with **Bob’s public key** for confidentiality.
    - She then signs the message by encrypting it again with **her own private key**, allowing Bob to verify the sender.
2. **Receiving and Decrypting**:
    - Bob first decrypts the message with **Alice’s public key** to verify her identity (authentication).
    - He then decrypts it with **his own private key** to access the original content (confidentiality).

![image 2](https://github.com/user-attachments/assets/791fcd0c-d761-4b7e-adae-e4811200e93c)


Diagram of how this final procedure works

<!-- TOC --><a name="digital-envelopes"></a>
## Digital Envelopes

Protects a message without needing to first arrange for sender and receiver to have the same secrete key.

1. Bob:
    1. Encrypt the message with the Random Symmetric Key
    2. Encrypt the Random Symmetric Key with Alice´s public Key
    3. Wrap all together in the digital envelope
2. Zelda → only has access to:
    1. Encrypted message by the key is in the digital envelope
    2. The key in the digital envelope is encrypted with the public key of Alice, so nobody but Alice can read it.
3. Alice:
    1. Decrypt the Random Symmetric Key with her private Key
    2. Decrypt the message with the decrypted Random Symmetric Key.

This way both have the  Random Symmetric Key and a message.

![Untitled_Diagram-Page-2](https://github.com/user-attachments/assets/9abf08e6-e38a-456e-bc34-285e2f38c74c)

<!-- TOC --><a name="public-key-infrastructure-pki-and-certificate-authorities-cas"></a>
## Public Key Infrastructure (PKI) and Certificate Authorities (CAs)

<!-- TOC --><a name="what-is-pki"></a>
### What is PKI?

**Public Key Infrastructure (PKI)** is a framework that enables secure, encrypted communication and authentication on a large scale, primarily by managing public-key encryption. PKI uses pairs of cryptographic keys—public and private—and relies on trusted entities known as **Certificate Authorities (CAs)** to issue and verify digital certificates that associate public keys with specific entities, like individuals, devices, or websites.

<!-- TOC --><a name="key-components-of-pki"></a>
### Key Components of PKI:

1. **Certificate Authority (CA)**: The trusted organization that issues and manages digital certificates, verifying the identity of certificate requestors.
2. **Digital Certificate**: A digital file that binds a public key to an entity’s identity, which could be a person, organization, or website. It includes the entity's public key, identification information, and the CA's digital signature.
3. **Registration Authority (RA)**: Acts as a mediator for the CA, verifying the identity of entities requesting a certificate and then sending requests to the CA for certificate issuance.
4. **Certificate Revocation List (CRL)**: A list maintained by the CA containing certificates that have been revoked before their expiration date.

<!-- TOC --><a name="how-pki-works-with-certificate-authorities"></a>
### How PKI Works with Certificate Authorities:

1. **Key Generation**:
    - The user or entity (e.g., a website or organization) generates a public-private key pair.
    - The public key will be shared publicly, while the private key remains confidential and secure.
2. **Certificate Request**:
    - The entity generates a **Certificate Signing Request (CSR)**, which includes the public key and other identifying information (e.g., organization name, domain name for websites).
    - The CSR is sent to the CA for verification.
3. **Identity Verification**:
    - The **CA or RA** verifies the identity of the requesting entity to ensure it is legitimate.
    - For example, for a website certificate, the CA checks domain ownership; for organizational certificates, it may check company registration.
4. **Certificate Issuance**:
    - Once the CA verifies the request, it issues a **digital certificate** that binds the entity's identity to its public key.
    - The certificate includes information such as:
        - The entity’s public key
        - The entity’s identifying details (e.g., domain name, organization name)
        - The CA’s digital signature, proving that the certificate was issued by a trusted authority
        - Expiration date of the certificate
    - This digital certificate is now trusted by other users and systems, as it has been signed by the CA.
5. **Certificate Validation**:
    - When a user or system connects to a certificate holder (e.g., a website), it receives the digital certificate and validates it by checking the CA's signature.
    - The user’s system checks the CA’s signature on the certificate against a list of trusted CA certificates stored in the browser or operating system.
    - If the CA signature is valid and the certificate has not expired or been revoked, the connection proceeds as secure.
6. **Ongoing Trust Management**:
    - **Certificate Revocation**: If a certificate is compromised or no longer trustworthy, the CA can revoke it. Users and systems can then check the CRL or an Online Certificate Status Protocol (OCSP) to verify the certificate’s validity in real time.
    - **Renewal and Expiration**: Certificates are issued with an expiration date, after which they are no longer trusted. Entities need to renew their certificates regularly to maintain secure communication.

<!-- TOC --><a name="example"></a>
### Example

Bob try to connect with Alice

1. Bob:
    1. Make a hash of its ID, his public key and the CA information. Lets call the `HASH1`.
    2. Share the `HASH1` with Alice
2. The CA:
    1. Make the same `HASH1`.
    2. Encrypt the `HASH1` with his private key that generates the `Signed Certificate`.
    3. Send the `Signed Certificate` to Alice
3. Alice:
    1. Receive `Signed Certificate`.
    2. Decrypt the `Signed Certificate` and get the `HASH2`
    3. Compare the `HASH2` with `HASH1` (received from **Bob), if they match, Alice is talking with Bob, otherwise no.**

![Untitled_Diagram](https://github.com/user-attachments/assets/4348cfde-5048-4c6c-8000-b8fa7c253e34)


<!-- TOC --><a name="benefits-of-pki-and-cas"></a>
### Benefits of PKI and CAs:

- **Authentication**: Ensures that the entity using the certificate is genuine (e.g., a website or organization).
- **Confidentiality**: Encrypts communication so only the intended recipient can read it.
- **Integrity**: The CA's signature and the structure of the digital certificate prevent tampering, ensuring that the public key is securely bound to the entity’s identity.
- **Non-repudiation**: Entities cannot deny ownership of a message signed with their private key since the public key in their certificate verifies it.

<!-- TOC --><a name="rsa-rivest-shamir-adleman"></a>
# RSA (Rivest, Shamir, Adleman)

Most widely accepted and implemented approach to public-key encryption

<aside>


Elliptic curve cryptography (ECC) is other asymmetric encryption algorithm, securely like RSA, but with much smaller keys.

</aside>

Steps

1. Randomly and independently select 2 large prime numbers `p` and `q` such that `p ≠ q`.
2. Calculate `n` where `n = p * q`.
3. Calculate `f` where `f = (p-1)*(q-1)`.
4. Select and integer `e` (encryption exponent) such that `1 < e < f` and other constrains
5. Calculate `d` (decryption exponent) where `d*e mod f = 1`.
6. Given `p,q,f,e,d` we have:
    1. Public Key is the combination of `n` and `e`.
    2. Private key is the combination of `n` and `d`.

So in example where Bob send a message to Alice

1. The cipher `c = (m^e) mod n` where `n` and `e` are the public key of Alice and `m` is the message.
2. The message `m = (c^d) mod n` where `n` and `d` are the private key of Alice.

> RSA’s main security foundation relies upon the fact that given 2 large prime numbers, it is easy to get `n`, but probability of getting those prime number from `n` is almost impossible.
>
