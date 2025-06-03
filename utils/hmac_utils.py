import hmac
import hashlib

def compute_hmac(key: bytes, message:bytes) -> bytes:
    """
    Computes HMAC using SHA-256.

    :param key: The secret key used for HMAC.
    :param message: The message to be hashed.
    :return: The computed HMAC as bytes.
    """
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_hmac(key: bytes, message: bytes, tag:bytes) -> bool:
    """
    Verifies the HMAC of a message against a provided tag.
    :param key: The secret key used for HMAC.
    :param message: The original message to verify.
    :param tag: The HMAC tag to verify against.
    :return: True if the HMAC matches, False otherwise.
    """
    if not isinstance(key, bytes) or not isinstance(message, bytes) or not isinstance(tag, bytes):
        raise ValueError("Key, message, and tag must be of type 'bytes'.")
    
    expected = compute_hmac(key, message)
    print(f"🔍 Expected HMAC: {expected.hex()}")
    print(f"🔍 Provided HMAC: {tag.hex()}")
    return hmac.compare_digest(expected, tag)