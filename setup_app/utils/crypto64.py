import os
import re
import base64
import json

from collections import OrderedDict

from setup_app.pylib.pyDes import triple_des, ECB, PAD_PKCS5

from setup_app import paths
from setup_app import static
from setup_app.config import Config

class Crypto64:

    def get_ssl_subject(self, ssl_fn):
        retDict = {}
        cmd = paths.cmd_openssl + ' x509  -noout -subject -nameopt RFC2253 -in {}'.format(ssl_fn)
        s = self.run(cmd, shell=True)
        s = s.strip() + ','

        for k in ('emailAddress', 'CN', 'O', 'L', 'ST', 'C'):
            rex = re.search('{}=(.*?),'.format(k), s)
            retDict[k] = rex.groups()[0] if rex else ''

        return retDict

    def obscure(self, data=""):
        engine = triple_des(Config.encode_salt, ECB, pad=None, padmode=PAD_PKCS5)
        data = data.encode('utf-8')
        en_data = engine.encrypt(data)
        encoded_pw = base64.b64encode(en_data)
        return encoded_pw.decode('utf-8')

    def unobscure(self, data=""):
        engine = triple_des(Config.encode_salt, ECB, pad=None, padmode=PAD_PKCS5)
        cipher = triple_des(Config.encode_salt)
        decrypted = cipher.decrypt(base64.b64decode(data), padmode=PAD_PKCS5)
        return decrypted.decode('utf-8')

    def gen_cert(self, suffix, password, user='root', cn=None, truststore_fn=None):
        self.logIt('Generating Certificate for %s' % suffix)
        key_with_password = '%s/%s.key.orig' % (Config.certFolder, suffix)
        key = '%s/%s.key' % (Config.certFolder, suffix)
        csr = '%s/%s.csr' % (Config.certFolder, suffix)
        public_certificate = '%s/%s.crt' % (Config.certFolder, suffix)
        if not truststore_fn:
            truststore_fn = Config.defaultTrustStoreFN

        self.run([paths.cmd_openssl,
                  'genrsa',
                  '-des3',
                  '-out',
                  key_with_password,
                  '-passout',
                  'pass:%s' % password,
                  '2048'
                  ])
        self.run([paths.cmd_openssl,
                  'rsa',
                  '-in',
                  key_with_password,
                  '-passin',
                  'pass:%s' % password,
                  '-out',
                  key
                  ])

        certCn = cn
        if certCn == None:
            certCn = Config.hostname

        self.run([paths.cmd_openssl,
                  'req',
                  '-new',
                  '-key',
                  key,
                  '-out',
                  csr,
                  '-subj',
                  '/C=%s/ST=%s/L=%s/O=%s/CN=%s/emailAddress=%s' % (Config.countryCode, Config.state, Config.city, Config.orgName, certCn, Config.admin_email)
                  ])
        self.run([paths.cmd_openssl,
                  'x509',
                  '-req',
                  '-days',
                  '365',
                  '-in',
                  csr,
                  '-signkey',
                  key,
                  '-out',
                  public_certificate
                  ])
        self.run([paths.cmd_chown, '%s:%s' % (user, user), key_with_password])
        self.run([paths.cmd_chmod, '700', key_with_password])
        self.run([paths.cmd_chown, '%s:%s' % (user, user), key])
        self.run([paths.cmd_chmod, '700', key])

        self.run([Config.cmd_keytool, "-import", "-trustcacerts", "-alias", "%s_%s" % (Config.hostname, suffix), \
                  "-file", public_certificate, "-keystore", truststore_fn, \
                  "-storepass", "changeit", "-noprompt"])

    def prepare_extension_scripts(self, extensions=[]):
        self.logIt("Preparing scripts")
        try:
            if not os.path.exists(Config.extensionFolder):
                return None

            for extensionType in os.listdir(Config.extensionFolder):
                extensionTypeFolder = os.path.join(Config.extensionFolder, extensionType)
                if not os.path.isdir(extensionTypeFolder):
                    continue

                for scriptFile in os.listdir(extensionTypeFolder):
                    scriptFilePath = os.path.join(extensionTypeFolder, scriptFile)

                    extensionScriptName = '%s_%s' % (extensionType, os.path.splitext(scriptFile)[0])
                    extensionScriptName = extensionScriptName.lower()

                    if (False if extensions and not extensionScriptName in extensions else True):
                        # Prepare key for dictionary
                        
                        with open(scriptFilePath) as reader:
                            Config.templateRenderingDict[extensionScriptName] = json.dumps(reader.read())
                        self.logIt("Loaded script %s with type %s into %s" % (scriptFile, extensionType, extensionScriptName))

        except:
            self.logIt("Error loading scripts from %s" % Config.extensionFolder, True)

    def gen_keystore(self, suffix, keystoreFN, keystorePW, inKey, inCert, alias=None):

        self.logIt("Creating keystore %s" % suffix)
        # Convert key to pkcs12
        pkcs_fn = '%s/%s.pkcs12' % (Config.certFolder, suffix)
        self.run([paths.cmd_openssl,
                  'pkcs12',
                  '-export',
                  '-inkey',
                  inKey,
                  '-in',
                  inCert,
                  '-out',
                  pkcs_fn,
                  '-name',
                  alias if alias else Config.hostname,
                  '-passout',
                  'pass:%s' % keystorePW
                  ])
        # Import p12 to keystore
        import_cmd = [Config.cmd_keytool,
                  '-importkeystore',
                  '-srckeystore',
                  '%s/%s.pkcs12' % (Config.certFolder, suffix),
                  '-srcstorepass',
                  keystorePW,
                  '-srcstoretype',
                  'PKCS12',
                  '-destkeystore',
                  keystoreFN,
                  '-deststorepass',
                  keystorePW,
                  '-deststoretype',
                  'JKS',
                  '-keyalg',
                  'RSA',
                  '-noprompt'
                  ]
        if alias:
            import_cmd += ['-alias', alias]

        self.run(import_cmd)


    def gen_openid_jwks_jks_keys(self, jks_path, jks_pwd, jks_create=True, key_expiration=None, dn_name=None, key_algs=None, enc_keys=None):
        self.logIt("Generating oxAuth OpenID Connect keys")

        if dn_name == None:
            dn_name = Config.default_openid_jks_dn_name

        if key_algs == None:
            key_algs = Config.default_key_algs

        if key_expiration == None:
            key_expiration = Config.default_key_expiration

        if not enc_keys:
            enc_keys = key_algs

        # We can remove this once KeyGenerator will do the same
        if jks_create == True:
            self.logIt("Creating empty JKS keystore")
            # Create JKS with dummy key
            cmd = " ".join([Config.cmd_keytool,
                            '-genkey',
                            '-alias',
                            'dummy',
                            '-keystore',
                            jks_path,
                            '-storepass',
                            jks_pwd,
                            '-keypass',
                            jks_pwd,
                            '-dname',
                            '"%s"' % dn_name])
            self.run([cmd], shell=True)

            # Delete dummy key from JKS
            cmd = " ".join([Config.cmd_keytool,
                            '-delete',
                            '-alias',
                            'dummy',
                            '-keystore',
                            jks_path,
                            '-storepass',
                            jks_pwd,
                            '-keypass',
                            jks_pwd,
                            '-dname',
                            '"%s"' % dn_name])
            self.run([cmd], shell=True)

        cmd = " ".join([Config.cmd_java,
                        "-Dlog4j.defaultInitOverride=true",
                        "-cp", Config.non_setup_properties['oxauth_client_jar_fn'], 
                        Config.non_setup_properties['key_gen_path'],
                        "-keystore",
                        jks_path,
                        "-keypasswd",
                        jks_pwd,
                        "-sig_keys",
                        "%s" % key_algs,
                        "-enc_keys",
                        "%s" % enc_keys,
                        "-dnname",
                        '"%s"' % dn_name,
                        "-expiration",
                        "%s" % key_expiration])

        output = self.run([cmd], shell=True)

        if output:
            return output.splitlines()

    def export_openid_key(self, jks_path, jks_pwd, cert_alias, cert_path):
        self.logIt("Exporting oxAuth OpenID Connect keys")

        cmd = " ".join([Config.cmd_java,
                        "-Dlog4j.defaultInitOverride=true",
                        "-cp",
                        Config.non_setup_properties['oxauth_client_jar_fn'], 
                        Config.non_setup_properties['key_export_path'],
                        "-keystore",
                        jks_path,
                        "-keypasswd",
                        jks_pwd,
                        "-alias",
                        cert_alias,
                        "-exportfile",
                        cert_path])
        self.run(['/bin/sh', '-c', cmd])

    def write_openid_keys(self, fn, jwks):
        self.logIt("Writing oxAuth OpenID Connect keys")

        if not jwks:
            self.logIt("Failed to write oxAuth OpenID Connect key to %s" % fn)
            return

        self.backupFile(fn)

        try:
            jwks_text = '\n'.join(jwks)
            self.writeFile(fn, jwks_text)
            self.run([Config.cmd_chown, 'jetty:jetty', fn])
            self.run([Config.cmd_chmod, '600', fn])
            self.logIt("Wrote oxAuth OpenID Connect key to %s" % fn)
        except:
            self.logIt("Error writing command : %s" % fn, True)


