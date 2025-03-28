This is an illustrative prototype in Python that demonstrates core ideas from our proposal on a high level. It includes:

1. **Key Generation and (Simulated) RSA Key Exchange**  
   - We generate an RSA public/private key pair.  
   - We simulate a client obtaining the server's public key and using it to encrypt a secret symmetric key (for the custom cipher).  
   - In a real-world scenario, you would use a secure key-exchange protocol (e.g., Diffie-Hellman or ECC-based).

2. **Custom Block Cipher**  
   - A minimal Substitution-Permutation (SP) round function:
     - **Substitution**: A small S-box to introduce nonlinearity.
     - **Permutation**: A simple bit permutation or shift to spread out bits.
   - A key schedule that derives round subkeys from the main key.

Our encryption algorithm will use a form of hybrid enryption where key echange is done using public/private key pairs created using the RSA algorithm, and encryption is done with a shared symmetric key using a block cipher. The key exchange is found in exchange.py, and the encryption is found in encryption.py