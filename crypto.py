from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class crypto():
    @staticmethod
    def encrypt_RSA(public_key_loc, message):
        '''
        param: public_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''

        key = open(public_key_loc, "r").read()
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(message.encode())  # [1:]
        # encrypted = encrypted.decode("utf-8")#.replace("'", '"')
        # print ("minha chave é: {0}".format([str(encrypted)]))
        # return str(encrypted)[2:-1]
        return (encrypted)  # .decode('utf8')

    @staticmethod
    def decrypt_RSA(private_key_loc, encrypted_message):
        '''
        param: public_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''

        key = open(private_key_loc, "r").read()
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.decrypt(encrypted_message)

        return str(encrypted)
