from tinyec import registry
import secrets

curve = registry.get_curve('secp256r1')


def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]


def ecc_calc_encryption_keys(pub_key):
    """
        Alice give public key and receive the secret key and Bob public key
    """
    cipher_text_prikey = secrets.randbelow(curve.field.n)
    cipher_text_pubkey = cipher_text_prikey * curve.g
    shared_ecc_key = pub_key * cipher_text_prikey
    return shared_ecc_key, cipher_text_pubkey


def ecc_calc_decryption_key(priv_key, cipher_text_pubkey):
    """
        Alice calc secret key from her side, her private key * Bob public key
    """
    shared_ecc_key = cipher_text_pubkey * priv_key
    return shared_ecc_key


def get_my_key():
    """
        Alice generate her private key and public key
    """
    priv_key = secrets.randbelow(curve.field.n)
    pub_key = priv_key * curve.g
    print("My private key: ", hex(priv_key))
    print("My public key: ", compress_point(pub_key))
    return priv_key, pub_key


priv_key, pub_key = get_my_key()

encrypt_key, cipher_text_pubkey = ecc_calc_encryption_keys(pub_key)
print("Encryption key: ", compress_point(encrypt_key))

decryp_key = ecc_calc_decryption_key(priv_key, cipher_text_pubkey)
print("Decryption key: ", compress_point(decryp_key))
