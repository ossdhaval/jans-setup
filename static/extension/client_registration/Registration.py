# Copyright (c) 2021, Gluu
#
# Author: Yuriy Zabrovarnyy
#

from io.jans.model.custom.script.type.client import ClientRegistrationType
from io.jans.service.cdi.util import CdiUtil
from io.jans.as.model.util import JwtUtil
from io.jans.as.model.util import CertUtils
from java.security.cert import X509Certificate

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
        X509Certificate cert = CertUtils.x509CertificateFromPem(configurationAttributes.get("certProperty"))
        cn = CertUtils.getCN(cert)
        print "Client registration. cn: " + cn

        client.setDn("inum=" + cn + ",ou=clients,o=jans")
        client.setClientId(cn)

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

