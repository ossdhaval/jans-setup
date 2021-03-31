# Copyright (c) 2021, Gluu
#
# Author: Yuriy Zabrovarnyy
#

from io.jans.model.custom.script.type.client import ClientRegistrationType
from io.jans.service.cdi.util import CdiUtil
from io.jans.as.model.util import JwtUtil

import java

class ClientRegistration(ClientRegistrationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "Client registration. Initialization"
        print "Client registration. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "Client registration. Destroy"
        print "Client registration. Destroyed successfully"
        return True

    def createClient(self, registerRequest, client, configurationAttributes):
        print "Client registration. CreateClient method"
        return True

    def updateClient(self, registerRequest, client, configurationAttributes):
        print "Client registration. UpdateClient method"
        return True

    def getApiVersion(self):
        return 11

    def getSoftwareStatementHmacSecret(self, context):
        return ""

    def getSoftwareStatementJwks(self, context):
        print "Client registration. getSoftwareStatementJwks method"
        return JwtUtil.getJSONWebKeys("https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks").toString()

    def getDcrHmacSecret(self, context):
        return ""

    def getDcrJwks(self, context):
        print "Client registration. getDcrJwks method"
        return JwtUtil.getJSONWebKeys("https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks").toString()

