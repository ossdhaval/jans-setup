import os
import sys
import json
import subprocess
import uuid
import glob
import urllib
import ssl
import re
import inspect

from setup_app import paths
from setup_app.utils import base
from setup_app.static import InstallTypes, colors

from setup_app.config import Config
from setup_app.utils.setup_utils import SetupUtils
from setup_app.utils.db_utils import dbUtils
from setup_app.pylib.jproperties import Properties

class PropertiesUtils(SetupUtils):

    def getDefaultOption(self, val):
        return 'Yes' if val else 'No'
        

    def getPrompt(self, prompt, defaultValue=None):
        try:
            if defaultValue:
                user_input = input("%s [%s] : " % (prompt, defaultValue)).strip()
                if user_input == '':
                    return defaultValue
                else:
                    return user_input
            else:
                while True:
                    user_input = input("%s : " % prompt).strip()
                    if user_input != '':
                        return user_input

        except KeyboardInterrupt:
            sys.exit()
        except:
            return None

    def check_properties(self):
        self.logIt('Checking properties')

        while not Config.hostname:
            testhost = input('Hostname of this server: ').strip()
            if len(testhost.split('.')) >= 3:
                Config.hostname = testhost
            else:
                print('The hostname has to be at least three domain components. Try again\n')

        while not Config.ip:
            Config.ip = self.get_ip()

        while not Config.orgName:
            Config.orgName = input('Organization Name: ').strip()

        while not Config.countryCode:
            testCode = input('2 Character Country Code: ').strip()
            if len(testCode) == 2:
                Config.countryCode = testCode
            else:
                print('Country code should only be two characters. Try again\n')

        while not Config.city:
            Config.city = input('City: ').strip()

        while not Config.state:
            Config.state = input('State or Province: ').strip()

        if not Config.admin_email:
            tld = None
            try:
                tld = ".".join(self.hostname.split(".")[-2:])
            except:
                tld = Config.hostname
            Config.admin_email = "support@%s" % tld

        if not Config.encode_salt:
            Config.encode_salt = self.getPW() + self.getPW()

        if not Config.jans_max_mem:
            Config.jans_max_mem = int(base.current_mem_size * .83 * 1000) # 83% of physical memory

    def prompt_for_rdbm(self):
        while True:
            Config.rdbm_type = self.getPrompt("RDBM Type", Config.rdbm_type)
            if Config.rdbm_type in ('mysql', 'pgsql'):
                break
            print("Please enter mysql or pgsql")


        remote_local = input("Use remote RDBM [Y|n] : ")

        if remote_local.lower().startswith('n'):
            Config.rdbm_install_type = InstallTypes.LOCAL
            if not Config.rdbm_password:
                Config.rdbm_password = self.getPW()
        else:
            Config.rdbm_install_type = InstallTypes.REMOTE

        if Config.rdbm_install_type == InstallTypes.REMOTE:
            while True:
                Config.rdbm_host = self.getPrompt("  {} host".format(Config.rdbm_type.upper()), Config.rdbm_host)
                Config.rdbm_port = self.getPrompt("  {} port".format(Config.rdbm_type.upper()), Config.rdbm_port)
                Config.rdbm_db = self.getPrompt("  Jnas Database", Config.rdbm_db)
                Config.rdbm_user = self.getPrompt("  Jans Database Username", Config.rdbm_user)
                Config.rdbm_password = self.getPrompt("  Jans Database Password", Config.rdbm_password)

                result = dbUtils.sqlconnection()

                if result[0]:
                    print("  {}Successfully connected to {} server{}".format(colors.OKGREEN, Config.rdbm_type.upper(), colors.ENDC))
                    break
                else:
                    print("  {}Can't connect to {} server with provided credidentals.{}".format(colors.FAIL, Config.rdbm_type.upper(), colors.ENDC))
                    print("  ERROR:", result[1])


    def promptForProperties(self):


        if Config.installed_instance:
            print("This is previously installed instance. Available components will be prompted for installation.")

        else:
            promptForMITLicense = self.getPrompt("Do you acknowledge that use of the Janssen Server is under the Apache-2.0 license?", "N|y")[0].lower()
            if promptForMITLicense != 'y':
                sys.exit(0)

            # IP address needed only for Apache2 and hosts file update
            if Config.installHttpd:
                Config.ip = self.get_ip()

            detectedHostname = self.detect_hostname()

            if detectedHostname == 'localhost':
                detectedHostname = None

            while True:
                if detectedHostname:
                    Config.hostname = self.getPrompt("Enter hostname", detectedHostname)
                else:
                    Config.hostname = self.getPrompt("Enter hostname")

                if Config.hostname != 'localhost':
                    break
                else:
                    print("Hostname can't be \033[;1mlocalhost\033[0;0m")

            # Get city and state|province code
            Config.city = self.getPrompt("Enter your city or locality", Config.city)
            Config.state = self.getPrompt("Enter your state or province two letter code", Config.state)

            # Get the Country Code
            long_enough = False
            while not long_enough:
                countryCode = self.getPrompt("Enter two letter Country Code", Config.countryCode)
                if len(countryCode) != 2:
                    print("Country code must be two characters")
                else:
                    Config.countryCode = countryCode
                    long_enough = True

            Config.orgName = self.getPrompt("Enter Organization Name", Config.orgName)

            while True:
                Config.admin_email = self.getPrompt('Enter email address for support at your organization', Config.admin_email)
                if self.check_email(Config.admin_email):
                    break
                else:
                    print("Please enter valid email address")
            
            Config.jans_max_mem = self.getPrompt("Enter maximum RAM for applications in MB", str(Config.jans_max_mem))

            self.prompt_for_rdbm()

            use_external_key_prompt = input('Use external key? [Y|n] : ')
            Config.use_external_key = not use_external_key_prompt.lower().startswith('n')

            if Config.use_external_key:
                while True:
                    ob_key_fn = self.getPrompt('  Openbanking Key File', Config.ob_key_fn)
                    if os.path.isfile(ob_key_fn):
                        Config.ob_key_fn = ob_key_fn
                        break
                    print("  {}File {} does not exist{}".format(colors.WARNING, ob_key_fn, colors.ENDC))

                while True:
                    ob_cert_fn = self.getPrompt('  Openbanking Certificate File', Config.ob_cert_fn)
                    if os.path.isfile(ob_cert_fn):
                        Config.ob_cert_fn = ob_cert_fn
                        break
                    print("  {}File {} does not exist{}".format(colors.WARNING, ob_key_fn, colors.ENDC))

                Config.ob_alias = self.getPrompt('  Openbanking Key Alias', Config.ob_alias)

propertiesUtils = PropertiesUtils()
