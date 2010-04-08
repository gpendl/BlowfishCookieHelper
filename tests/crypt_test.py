import unittest

from products.DVAGCookiePlugin.utils import Crypt

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
                ('', '')
            )

class DecryptEncryptCheck(unittest.TestCase):
    
    def test_cycle(self):
        
        for pt, pph in d_values:
            c = Crypt(pph)
            u = c.encrypt(pt)
            dc = c.decrypt(u)
            self.assertEqual(dc, pt) 
            
        



if __name__ == "__main__":
    unittest.main()   