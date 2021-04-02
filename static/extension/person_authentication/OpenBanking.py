from java.util import Collections, HashMap, HashSet, ArrayList, Arrays, Date
from io.jans.service.cdi.util import CdiUtil
from io.jans.model.custom.script.type.auth import PersonAuthenticationType
from io.jans.as.server.security import Identity
from io.jans.util import StringHelper
from io.jans.jsf2.service import FacesService
from javax.faces.context import FacesContext
from io.jans.jsf2.message import FacesMessages
from io.jans.as.server.util import ServerUtil
from io.jans.as.server.service import UserService, SessionIdService,AuthenticationService
from io.jans.as.common.model.common import User 
from java.lang import String

from com.nimbusds.jose import EncryptionMethod;
from com.nimbusds.jose import JWEAlgorithm;
from com.nimbusds.jose import JWEHeader;
from com.nimbusds.jose import JWEObject;
from com.nimbusds.jose import Payload;
from com.nimbusds.jose.crypto import DirectDecrypter;
from com.nimbusds.jose.crypto import DirectEncrypter;
import time
import java
import sys
import os

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis   

    def init(self, customScript, configurationAttributes):
        # TODO: ideally this will come from a configuration
        self.sharedSecret =  "kXp2s5v8y/B?E(H+MbPeShVmYq3t6w9z"
        print "OpenBanking Person authentication script initialized."
        return True   

    def destroy(self, configurationAttributes):
        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):
        return None
    
    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
    	print "OpenBanking. Authenticate. Step %s " % step
        
        sessionData =  ServerUtil.getFirstValue(requestParameters, "sessionData") 
 
        jweObject = JWEObject.parse(sessionData)
        #Decrypt
        jweObject.decrypt(DirectDecrypter((String(self.sharedSecret)).getBytes()))

        # Get the plain text
        payload = jweObject.getPayload()
        print "session payload - "+payload.toString()
        authenticationService = CdiUtil.bean(AuthenticationService)
               
               # TODO: create a dummy user and authenticate
        newUser = User()
        uid = "ob_"+str(int(time.time()*1000.0))
        newUser.setAttribute("uid",uid)
               
               #TODO: add a new parameter called expiry and set expiry time 
               # TODO:  A clean up task should be written which will delete this record
        userService = CdiUtil.bean(UserService)
        userService.addUser(newUser, True)
               # TODO: create a dummy user and authenticate
        logged_in = authenticationService.authenticate(uid)

        openbanking_intent_id = "ert2342-23423-4322"  #resultObject.get("login").get("account")
        acr_ob = "something"#resultObject.get("login").get("acr")
               
               # add a few things in session
        sessionIdService = CdiUtil.bean(SessionIdService)
        sessionId = sessionIdService.getSessionId() # fetch from persistence
        sessionId.getSessionAttributes().put("openbanking_intent_id",openbanking_intent_id )
        sessionId.getSessionAttributes().put("acr_ob", acr_ob )
        print "OpenBanking. Successful authentication"
        return True

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "OpenBanking. prepare for step... %s" % step 
        #extract intent id from request object which is an encoded JWT
        request = ServerUtil.getFirstValue(requestParameters, "request")
        #request = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0..oq8dqcaM-3wmg-Lx.szxCZE4H9QayTIr7ZXZ1YoQmCOtmvWQP06LKjJy9jqPFZ7-SnMkWeDNxqd3559pfNU-SyH555r7VagYYqMKMpoBm.zUe6Slv-2ZRLi55jz5Z7kA"
        jweObject = JWEObject.parse(request)
        #Decrypt
        jweObject.decrypt(DirectDecrypter((String(self.sharedSecret)).getBytes()))

        # Get the plain text
        print "jweobject : %s " % jweObject
        payload = jweObject.getPayload()
        print "OpenBanking.Request payload containing intent id- %s- " % payload 
        print " open intent id %s - " % payload.toJSONObject().get("openbanking_intent_id") 
        
        # A successful authorization will always return the `result` claim with login and consent details
        if payload.toJSONObject().get("openbanking_intent_id") is not None:
            openbanking_intent_id = str(payload.toJSONObject().get("openbanking_intent_id"))
            print "openbanking_intent_id %s" % openbanking_intent_id
            #sessionId = CdiUtil.bean(SessionIdService).getSessionId()
            
            redirectURL = "https://bank-op.gluu.org/" #self.getRedirectURL (openbanking_intent_id, sessionId)
     
            print "OpenBanking. Redirecting to ... %s " % redirectURL 
            facesService = CdiUtil.bean(FacesService)
            facesService.redirectToExternalURL(redirectURL)
            return True
		
        print "OpenBanking. Call to Gluu's /authorize endpoint should contain openbanking_intent_id as an encoded JWT"
        return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1
    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1
    def getPageForStep(self, configurationAttributes, step):
        print "OpenBanking. getPageForStep... %s" % step
        if step == 1:
            return "/auth/redirect.xhtml"
        
        return ""
    def getExtraParametersForStep(self, configurationAttributes, step):
          return Arrays.asList("openbanking_intent_id", "acr_ob")

    def logout(self, configurationAttributes, requestParameters):
        return True
        

        
