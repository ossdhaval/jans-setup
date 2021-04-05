# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2021, Gluu
#
# Author: Yuriy Zabrovarnyy
#
#

from org.gluu.model.custom.script.type.introspection import IntrospectionType
from java.lang import String
from org.gluu.oxauth.model.common import AuthorizationGrantList
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import GrantService
from org.gluu.oxauth.model.ldap import TokenType
from org.gluu.oxauth.model.ldap import TokenLdap

class Introspection(IntrospectionType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "Introspection script (retain claims). Initializing ..."
        print "Introspection script (retain claims). Initialized successfully"

        return True

    def destroy(self, configurationAttributes):
        print "Introspection script (retain claims). Destroying ..."
        print "Introspection script (retain claims). Destroyed successfully"
        return True

    def getApiVersion(self):
        return 1

    # Returns boolean, true - apply introspection method, false - ignore it.
    # This method is called after introspection response is ready. This method can modify introspection response.
    # Note :
    # responseAsJsonObject - is org.codehaus.jettison.json.JSONObject, you can use any method to manipulate json
    # context is reference of org.gluu.oxauth.service.external.context.ExternalIntrospectionContext (in https://github.com/GluuFederation/oxauth project, )
    def modifyResponse(self, responseAsJsonObject, context):
        print "modifyResponse invoked"

        authorizationGrantList = CdiUtil.bean(AuthorizationGrantList)
        grantService = CdiUtil.bean(GrantService)

        refreshToken = context.getHttpRequest().getParameter("refresh_token")
        if refreshToken is None:
            print "No refresh token parameter. Put original claim - claim1=value1"
            responseAsJsonObject.accumulate("claim1", "value1") # AT1

            # save it also in refresh token
            grants = grantService.getGrantsByGrantId(context.getTokenGrant().getGrantId())
            RT1 = {}
            for grant in grants:
                if (grant.getTokenTypeEnum() == TokenType.REFRESH_TOKEN):
                    RT1 = grant

            print "RT1 hashed code: " + RT1.getTokenCode()
            RT1.getAttributes().getAttributes().put("claim1", "value1")
            grantService.mergeSilently(RT1)

            return True

        responseAsJsonObject.accumulate("refresh_token", refreshToken)
        print "Refresh token: " + refreshToken

        clientId = context.getTokenGrant().getClientId()
        print "ClientId: " + clientId

        grantId = authorizationGrantList.getAuthorizationGrantByRefreshToken(clientId, refreshToken).getGrantId()
        print "grantId: " + grantId
        responseAsJsonObject.accumulate("grant_id", grantId)

        grants = grantService.getGrantsByGrantId(grantId)

        RT = {}
        for grant in grants:
            if (grant.getTokenTypeEnum() == TokenType.REFRESH_TOKEN):
                RT = grant
        print "RT hashed code: " + RT.getTokenCode()


        valueFromAT = RT.getAttributes().getAttributes().get("claim1")
        print "valueFromAT: " + valueFromAT
        responseAsJsonObject.accumulate("claim1", valueFromAT)

        return True