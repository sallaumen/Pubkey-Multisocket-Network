from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

class crypto():
    @staticmethod
    def encrypt_RSA(private_key_loc, message):
        '''
        param: private_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''

        key = open(private_key_loc, "r").read()
        digest = SHA256.new()
        digest.update(message.encode())

        signer = RSA.importKey(key)

        signed = signer.sign(0, digest)

        return signed, digest.digest()

    @staticmethod
    def decrypt_RSA(public_key_loc, signed_message, digest, message):
        '''
        param: public_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''
        digest_new = SHA256.new()
        digest_new.update(message.encode())

        key = open(public_key_loc, "r").read()
        verifier = RSA.importKey(key)

        decoded_digest = base64.decodestring(digest.encode())
        verified = verifier.verify(digest_new.digest(), signed_message)

        return decoded_digest == digest_new.digest(), verified
