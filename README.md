# Asymmetric_Encryption_RSA
## RSA (Rivest–Shamir–Adleman) is a widely used asymmetric encryption algorithm, named after its inventors, that secures data using two mathematically linked keys: a public key for encrypting messages and a private key for decrypting them. 
<img src="https://github.com/AbhishekGandre/Asymmetric_Encryption_RSA/blob/main/RSA-Encryption-Works.png"></img>
# How RSA Encryption Works
## Key Generation: Two large prime numbers, p and q, are chosen to create a modulus n (n = p * q). These primes are kept secret, while n is used for both the public and private keys. 
## Public Key: A public key is created using n and an encryption exponent e (public key = n, e). This public key can be shared with anyone who needs to send an encrypted message. 
## Private Key: A private key is also created, consisting of n and a decryption exponent d (private key = n, d). This key must be kept secret by the owner and is used to decrypt messages. 
## Encryption: When someone wants to send a secret message, they use the recipient's public key (n, e) to encrypt their data. The message is converted into a ciphertext. 
## Decryption: The recipient uses their corresponding private key (n, d) to decrypt the ciphertext, recovering the original message. 
# Key Features
## Asymmetric: It uses two different keys for encryption and decryption, unlike symmetric encryption, which uses a single key. 
## Public-Key Cryptography: The public key is freely distributed, enabling broad secure communication, while the private key remains secure and private. 
## Security: Its security is based on the mathematical challenge of factoring the large composite number n into its original prime factors p and q. 
## Non-Repudiation: RSA can provide non-repudiation, meaning a sender cannot deny having sent a message, especially when used with digital signatures. 
# Applications
## Secure Communication: Widely used in online banking, secure email, and secure identification to protect sensitive data. 
## Virtual Private Networks (VPNs): Establishes secure connections for remote network access. 
## Digital Signatures: Secures data integrity and provides authentication through digital signatures. 
