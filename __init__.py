##############################################################################
#
# PlonePAS - Adapt PluggableAuthService for use in Plone
# Copyright (C) 2005 Enfold Systems, Kapil Thangavelu, et al
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
"""
"""

from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService import registerMultiPlugin
from Products.CMFPlone import utils as plone_utils



#################################
# plugins

from plugins import cookie_handler




try:

    registerMultiPlugin( cookie_handler.BlowfishExtendedCookieAuthHelper.meta_type )
except RuntimeError:
    # make refresh users happy
    pass

def initialize(context):


    context.registerClass( cookie_handler.BlowfishExtendedCookieAuthHelper,
                           permission = add_user_folders,
                           constructors = ( cookie_handler.manage_addBlowfishExtendedCookieAuthHelperForm,
                                            cookie_handler.manage_addBlowfishExtendedCookieAuthHelper ),
                           visibility = None
                           )
                           
