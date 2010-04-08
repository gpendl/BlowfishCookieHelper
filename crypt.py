import base64
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA256

class Crypt:
    """Crypto cipher to make it easier to encrypt and decrypt using Blowfish.
    This module also works with qrypto perl and PHP modules"""

    def __init__(self, secret_phrase):
        self.BLOCK_SIZE = 8
        self.secret_phrase = secret_phrase
        digest = SHA256.new(secret_phrase).hexdigest()
        self.__iv  = digest[:8]
        self.__key = digest[8:]

    def decrypt(self, encrypted_encoded):
        decoded = base64.b64decode(encrypted_encoded)
        crypto = Blowfish.new(self.__key, Blowfish.MODE_CBC, self.__iv)
        return self.__trim(crypto.decrypt(decoded))

    def encrypt(self, plain_text):
        padded = self.__pad(plain_text)
        crypto = Blowfish.new(self.__key, Blowfish.MODE_CBC, self.__iv)
        encrypted = crypto.encrypt(padded)
        return base64.b64encode(encrypted)

    def __pad (self, plaintext):
        mod = len(plaintext) % self.BLOCK_SIZE
        if (mod == 0):
            return plaintext
        else:
            to_pad = self.BLOCK_SIZE - mod
            pad = '\0';
            for x in range(1, to_pad):
                pad += '\0'
            return plaintext + pad

    def __trim(self, text):
        if (text[-1:] == '\0'):
            return self.__trim(text[:-1])
        else:
            return text
    