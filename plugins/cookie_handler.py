""" Class: BlowfishExtendedCookieAuthHelper

Simply extends the standard CookieAuthHelper provided via regular
PluggableAuthService but overrides the updateCookie mechanism to
provide similar functionality as CookieCrumbler does... by giving
the portal the ability to provide a setAuthCookie method to provide
encryption and decryption by the blowfish algorithm - also the extraction ;)


$Id$
"""


from Products.BlowfishCookieHelper import crypt
from urllib import quote
from urllib import unquote
from Acquisition import aq_base
from AccessControl.SecurityInfo import ClassSecurityInfo
from Globals import InitializeClass, DTMLFile
from Products.PluggableAuthService.plugins.CookieAuthHelper \
    import CookieAuthHelper as BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import \
        ILoginPasswordHostExtractionPlugin, IChallengePlugin,  \
        ICredentialsUpdatePlugin, ICredentialsResetPlugin

from Products.CMFPlone.utils import log


def manage_addBlowfishExtendedCookieAuthHelper(self, id, title='',
                                       RESPONSE=None, **kw):
    """Create an instance of a extended cookie auth helper.
    """

    self = self.this()

    o = BlowfishExtendedCookieAuthHelper(id, title, **kw)
    self._setObject(o.getId(), o)
    o = getattr(aq_base(self), id)

    if RESPONSE is not None:
        RESPONSE.redirect('manage_workspace')

manage_addBlowfishExtendedCookieAuthHelperForm = DTMLFile("../zmi/ExtendedCookieAuthHelperForm", globals())



class BlowfishExtendedCookieAuthHelper(BasePlugin):
    """Multi-plugin which adds ability to override the updating of cookie via
    a setAuthCookie method/script.
    """

    meta_type = 'Blowfish Extended Cookie Auth Helper'
    security = ClassSecurityInfo()
    
    secret_phrase = "changeinproduction"
    
    
    _properties = BasePlugin._properties + (
                    { 'id'    : 'secret_phrase'
                    , 'label' : 'Blowfish Phrase'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    },
                    )

    
    _denc = crypt.Crypt(secret_phrase)
    
    def _get_denc(self):
        
        if self._denc.secret_phrase != self.secret_phrase:
            
            self._denc = crypt.Crypt(self.secret_phrase)
        
        return self._denc
            
            
    
        
    
    
    
    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):

        creds = {}
        cookie = request.get(self.cookie_name, '')

        login = request.get('__ac_name', '')

        if login and request.form.has_key('__ac_password'):
            # Look in the request for the names coming from the login form
            login = request.get('__ac_name', '')
            password = request.get('__ac_password', '')

            if login:
                creds['login'] = login
                creds['password'] = password
        elif cookie and cookie != 'deleted':

            
            cookie_val = self._get_denc().decrypt(unquote(cookie))

            login, password = cookie_val.split(':')

            creds['login'] = login
            creds['password'] = password
            
            
        if creds:
            creds['remote_host'] = request.get('REMOTE_HOST', '')

            try:
                creds['remote_address'] = request.getClientAddr()
            except AttributeError:
                creds['remote_address'] = request.get('REMOTE_ADDR', '')

        return creds
    
    security.declarePrivate('updateCredentials')
    def updateCredentials(self, request, response, login, new_password):
        """Override standard updateCredentials method
        """

        setAuthCookie = getattr(self, 'setAuthCookie', None)
        
        if setAuthCookie:
            
            cookie_val = '%s:%s' % (login, new_password)
            cookie_val = self._get_denc().encrypt(cookie_val)
            cookie_val = cookie_val.rstrip()
            setAuthCookie(response, self.cookie_name, quote(cookie_val))
            
        else:
            
            BasePlugin.updateCredentials(self, request, response, login, new_password)

    security.declarePublic('login')
    def login(self):
        """Set a cookie and redirect to the url that we tried to
        authenticate against originally.

        Override standard login method to avoid calling
        'return response.redirect(came_from)' as there is additional
        processing to ignore known bad come_from templates at
        login_next.cpy script.
        """
        request = self.REQUEST
        response = request['RESPONSE']

        login = request.get('__ac_name', '')
        password = request.get('__ac_password', '')

        pas_instance = self._getPAS()

        if pas_instance is not None:
            pas_instance.updateCredentials(request, response, login, password)


classImplements(BlowfishExtendedCookieAuthHelper,
                ILoginPasswordHostExtractionPlugin,
                IChallengePlugin,
                ICredentialsUpdatePlugin,
                ICredentialsResetPlugin,
               )

InitializeClass(BlowfishExtendedCookieAuthHelper)
