import unittest

from crypt import Crypt

"""
d_values = ('plaintext', 'passphrase')
"""

d_values = (
                ('servas', 'poidl'),
                ('gassdasdasd', 'asdasdasdasad'),
                ('kjkuererwerew', 'dfsdfddd'),
                ('asdfsdfsdfsdfsdfsdfsdfsdfsdf', 'se'),
                ('ssd', 'oida'),
                ('', '2'),
                ('', ''),
                (1212332, 121324324345435)
            )

class DecryptEncryptCheck(unittest.TestCase):
    cipher_key = 'my secret phrase'

    def test_ed_cycle(self):
        
        for pt, pph in d_values:
            
            c = Crypt(pph)
            u = c.encrypt(pt)
            dc = c.decrypt(u)
            
            print "assert equal: %s == %s" % (dc, str(pt))
            self.assertEqual(dc, str(pt)) 
            
    def test_module_name(self):

        c = Crypt(self.cipher_key)
        assert hasattr(c, '__module__')
        assert c.__module__ == 'CommonCrypt.Crypt'

    def test_attributes(self):
        c = Crypt(self.cipher_key)
        assert hasattr(c, 'BLOCK_SIZE')
        assert hasattr(c, 'decrypt')
        assert hasattr(c, 'encrypt')
        assert callable(c.decrypt)
        assert callable(c.encrypt)

    def test_private_attributes(self):
        c = Crypt(self.cipher_key)
        assert hasattr(c, 'iv') is False
        assert hasattr(c, 'key') is False
        assert hasattr(c, '_Crypt__iv')
        assert hasattr(c, '_Crypt__key')
        assert hasattr(c, '_Crypt__pad')
        assert hasattr(c, '_Crypt__trim')

    def test_blocksize(self):
        c = Crypt(self.cipher_key)
        assert c.BLOCK_SIZE == 8

    def test_encrypt(self):
        c = Crypt(self.cipher_key)
        encrypted = c.encrypt('some random plain text')
        assert encrypted == 'b1XdLeAJ54bz/ALcDd2FeAez7y5z33Le'

    def test_decrypt(self):
        c = Crypt(self.cipher_key)
        decrypted = c.decrypt('3b1b943Dcrqm179NGt3GnA==')
        assert decrypted == 'ace to the base'

        



if __name__ == "__main__":
    unittest.main()   
