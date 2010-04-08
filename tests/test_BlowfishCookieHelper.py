##############################################################################
#
# Copyright (c) 2001 Zope Corporation and Contributors. All Rights
# Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this
# distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
import unittest

from Products.PluggableAuthService.tests.conformance \
     import ILoginPasswordHostExtractionPlugin_conformance
from Products.PluggableAuthService.tests.conformance \
     import IChallengePlugin_conformance
from Products.PluggableAuthService.tests.conformance \
     import ICredentialsUpdatePlugin_conformance
from Products.PluggableAuthService.tests.conformance \
     import ICredentialsResetPlugin_conformance

from Products.PluggableAuthService.tests.test_PluggableAuthService \
     import FauxRequest, FauxResponse, FauxObject, FauxRoot, FauxContainer

from urllib import unquote, quote

from Products.BlowfishCookieHelper.crypt import Crypt

class FauxSettableRequest(FauxRequest):

    def set(self, name, value):
        self._dict[name] = value

class FauxCookieResponse(FauxResponse):

    def __init__(self):
        self.cookies = {}
        self.redirected = False
        self.status = '200'
        self.headers = {}

    def setCookie(self, cookie_name, cookie_value, path):
        self.cookies[(cookie_name, path)] = cookie_value

    def expireCookie(self, cookie_name, path):
        if (cookie_name, path) in self.cookies:
            del self.cookies[(cookie_name, path)]

    def redirect(self, location, status=302, lock=0):
        self.status = status
        self.headers['Location'] = location

def setAuthCookie(resp, cookie_name, cookie_value,cookie_path="/"):
    """
       a psycho to set the response
    """
    
    resp.setCookie( cookie_name, cookie_value, path=cookie_path)


class CookieAuthHelperTests( unittest.TestCase
                           , ILoginPasswordHostExtractionPlugin_conformance
                           , IChallengePlugin_conformance
                           , ICredentialsResetPlugin_conformance
                           ):

    def _getTargetClass( self ):

        from Products.BlowfishCookieHelper.plugins.cookie_handler \
            import BlowfishExtendedCookieAuthHelper as plugin

        return plugin

    def _makeOne( self, id='test', *args, **kw ):
        kw['cookie_name'] = "ac_users"
        return self._getTargetClass()( id=id, title="test", cookie_name=kw['cookie_name']  )

    def _makeTree( self ):

        rc = FauxObject( 'rc' )
        root = FauxRoot( 'root' ).__of__( rc )
        folder = FauxContainer( 'folder' ).__of__( root )
        object = FauxObject( 'object' ).__of__( folder )

        return rc, root, folder, object

    def test_extractCredentials_no_creds( self ):
        print "test_extractCredentials_no_creds"
        helper = self._makeOne()
        response = FauxCookieResponse()
        request = FauxRequest(RESPONSE=response)

        self.assertEqual( helper.extractCredentials( request ), {} )


        
        
    def test_update_crendetials_blowfish( self ):
        print "test_update_crendetials_blowfish"
        
        helper = self._makeOne()
        response = FauxCookieResponse()
        request = FauxSettableRequest(__ac_name='poidl',
                                      __ac_password='lazina',
        
                                      RESPONSE=response)
        

        
        helper.setAuthCookie = setAuthCookie
        secret_phrase = "poidllazina"
        denc = Crypt(secret_phrase)
        helper.updateCredentials(request, response, login="poidl", new_password="lazina")
        login = "poidl"
        password = "lazina"
        cc = denc.encrypt(login + ":" + password)

        
        self.assertEqual(unquote(response.cookies.values()[0]), denc.encrypt("poidl:lazina"))
        
        dic = helper.extractCredentials( request)
        
        self.assertEqual(dic['login'], login)
        self.assertEqual(dic['password'], password)


    def test_extractCredentials_with_form_creds( self ):
        print "test_extractCredentials_with_form_creds"
        helper = self._makeOne()
        response = FauxCookieResponse()
        request = FauxSettableRequest(__ac_name='foo',
                                      __ac_password='bar',
                                      RESPONSE=response)

        self.assertEqual(len(response.cookies), 0)
        print helper.extractCredentials(request)
        self.assertEqual(helper.extractCredentials(request),
                        {'login': 'foo',
                         'password': 'bar',
                         'remote_host': '',
                         'remote_address': ''})
        self.assertEqual(len(response.cookies), 0)

    def test_extractCredentials_with_deleted_cookie(self):
        # http://www.zope.org/Collectors/PAS/43
        # Edge case: The ZPublisher sets a cookie's value to "deleted"
        # in the current request if expireCookie is called. If we hit
        # extractCredentials in the same request after this, it would 
        # blow up trying to deal with the invalid cookie value.
        print "test_extractCredentials_with_deleted_cookie"
        helper = self._makeOne()
        response = FauxCookieResponse()
        req_data = { helper.cookie_name : 'deleted'
                   , 'RESPONSE' : response
                   }
        request = FauxSettableRequest(**req_data)
        self.assertEqual(len(response.cookies), 0)

        self.assertEqual(helper.extractCredentials(request), {})

    def test_challenge( self ):
        from zExceptions import Unauthorized
        rc, root, folder, object = self._makeTree()
        response = FauxCookieResponse()
        request = FauxRequest(RESPONSE=response)
        root.REQUEST = request

        helper = self._makeOne().__of__(root)

        helper.challenge(request, response)
        self.assertEqual(response.status, 302)
        self.assertEqual(len(response.headers), 1)


    def test_resetCredentials( self ):
        helper = self._makeOne()
        response = FauxCookieResponse()
        request = FauxRequest(RESPONSE=response)

        helper.resetCredentials(request, response)
        self.assertEqual(len(response.cookies), 0)

    def _test_loginWithoutCredentialsUpdate( self ):
        print "test login without update"
        helper = self._makeOne()
        response = FauxCookieResponse()
        request = FauxSettableRequest( __ac_name='foo'
                                     , __ac_password='bar'
                                     , RESPONSE=response
                                     )
        request.form['came_from'] = ''
        helper.REQUEST = request

        helper.login()
        print response.cookies
        #self.assertEqual(len(response.cookies), 0)


if __name__ == "__main__":
    unittest.main()

def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite( CookieAuthHelperTests ),
        ))

