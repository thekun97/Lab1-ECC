from tinyec import registry
from Crypto.Cipher import AES
import hashlib
import secrets
import binascii

curve = registry.get_curve('secp256r1')


def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]


def encrypt_AES_GCM(msg, secret_key):
    aes_cipher = AES.new(secret_key, AES.MODE_GCM)
    ciphertext, auth_tag = aes_cipher.encrypt_and_digest(msg)
    return (ciphertext, aes_cipher.nonce, auth_tag)


def decrypt_AES_GCM(ciphertext, nonce, auth_tag, secret_key):
    aes_cipher = AES.new(secret_key, AES.MODE_GCM, nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, auth_tag)
    return plaintext


def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()


def encrypt_ECC(msg, pub_key):
    ciphertext_privkey = secrets.randbelow(curve.field.n)
    shared_ecc_key = ciphertext_privkey * pub_key
    secret_key = ecc_point_to_256_bit_key(shared_ecc_key)
    ciphertext, nonce, auth_tag = encrypt_AES_GCM(msg, secret_key)
    ciphertext_pubkey = ciphertext_privkey * curve.g
    return (ciphertext, nonce, auth_tag, ciphertext_pubkey)


def decrypt_ECC(encrypted_msg, priv_key):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted_msg
    sharedECCKey = priv_key * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    print("symmetric key", compress_point(sharedECCKey))
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


msg = b'Dai hoc khoa hoc tu nhien'
print("original msg:", msg)
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

encryptedMsg = encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted msg:", binascii.hexlify(encryptedMsg[0]))
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg:", decryptedMsg)
