from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_keypair():
    # Generate a private key for use in the encryption algorithm
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    # Generate the public key from the private key
    public_key = private_key.public_key()

    return private_key, public_key

def pem_private_key(private_key, password=None):
    if password is None:
        # Unencrypted private key in PEM format
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem_private_key
    else:
        # Encrypt the private key with a password
        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        return encrypted_private_key

def pem_public_key(public_key):
    # Public key in PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public_key

def save_keypair(name_prefix, private_key, public_key):
    priv_key_name = "{}_private.pem".format(name_prefix)
    pub_key_name = "{}_public.pub".format(name_prefix)

    # Save the private key to a file
    private_key_file = open(priv_key_name, "w")
    private_key_file.write(private_key.decode())
    private_key_file.close()
    print("Private key saved to {}".format(priv_key_name))

    public_key_file = open(pub_key_name, "w")
    public_key_file.write(public_key.decode())
    public_key_file.close()
    print("Public key saved to {}".format(pub_key_name))

def generate_keys(name_prefix, encryption_password=None):
    # Generate a keypair
    raw_private_key, raw_public_key = generate_keypair()
    pem_priv_key, pem_pub_key = pem_private_key(raw_private_key, encryption_password), pem_public_key(raw_public_key)
    save_keypair(name_prefix, pem_priv_key, pem_pub_key)

def load_keypair(name_prefix, password=None):
    priv_key_name = "{}_private.pem".format(name_prefix)
    pub_key_name = "{}_public.pub".format(name_prefix)

    # Load the private key from a file
    with open(priv_key_name, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode() if password else None
        )

    # Load the public key from a file
    with open(pub_key_name, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key

def encrypt_message(message, public_key):
    # Encrypt the message using the public key
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()

def decrypt_message(ciphertext, private_key):
    # Decrypt the message using the private key
    plaintext = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

generate_keys("test_keypair", "password123")
priv_key, pub_key = load_keypair("test_keypair", "password123")
print("Private key loaded successfully.", priv_key)
print("Public key loaded successfully.", pub_key)
message = "Hello, World!"
print("Original message:", message)
encrypt_message = encrypt_message(message, pub_key)
print("Encrypted message:", encrypt_message)
decrypt_message = decrypt_message(encrypt_message, priv_key)
print("Decrypted message:", decrypt_message)
