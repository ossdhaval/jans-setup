#!/usr/bin/python3

import readline
import os
import sys
import time
import glob
import inspect
import zipfile
import shutil
import traceback
import code

from queue import Queue

queue = Queue()

os.environ['LC_ALL'] = 'C'
from setup_app.utils.arg_parser import arg_parser

argsp = arg_parser()

# first import paths and make changes if necassary
from setup_app import paths

# for example change log file location:
# paths.LOG_FILE = '/tmp/my.log'

from setup_app import static

# second import module base, this makes some initial settings
from setup_app.utils import base

# we will access args via base module
base.argsp = argsp

from setup_app.utils.package_utils import packageUtils

packageUtils.check_and_install_packages()

from setup_app.messages import msg
from setup_app.config import Config
from setup_app.utils.progress import jansProgress

from setup_app.setup_options import get_setup_options
from setup_app.utils import printVersion

from setup_app.utils.properties_utils import propertiesUtils
from setup_app.utils.setup_utils import SetupUtils
from setup_app.utils.collect_properties import CollectProperties

from setup_app.installers.jans import JansInstaller
from setup_app.installers.httpd import HttpdInstaller
from setup_app.installers.jre import JreInstaller
from setup_app.installers.jetty import JettyInstaller
from setup_app.installers.jython import JythonInstaller
from setup_app.installers.jans_auth import JansAuthInstaller
from setup_app.installers.config_api import ConfigApiInstaller
from setup_app.installers.jans_cli import JansCliInstaller
from setup_app.installers.rdbm import RDBMInstaller


# initialize config object
Config.init(paths.INSTALL_DIR)
Config.determine_version()

# we must initilize SetupUtils after initilizing Config
SetupUtils.init()

# get setup options from args
setupOptions = get_setup_options()

terminal_size = shutil.get_terminal_size()
tty_rows = terminal_size.lines
tty_columns = terminal_size.columns

# check if we are running in terminal
try:
    os.get_terminal_size()
except:
    argsp.no_progress = True

if not argsp.n:
    base.check_resources()

# pass progress indicator to Config object
Config.pbar = jansProgress

for key in setupOptions:
    setattr(Config, key, setupOptions[key])

jansInstaller = JansInstaller()
jansInstaller.initialize()

print()
print("Installing Janssen Server...\n\nFor more info see:\n  {}  \n  {}\n".format(paths.LOG_FILE, paths.LOG_ERROR_FILE))
print("Detected OS     :  {} {} {}".format('snap' if base.snap else '', base.os_type, base.os_version))
print("Janssen Version :  {}".format(Config.oxVersion))
print("Detected init   :  {}".format(base.os_initdaemon))
print("Detected Apache :  {}".format(base.determineApacheVersion()))
print()

collectProperties = CollectProperties()
if os.path.exists(Config.jans_properties_fn):
    collectProperties.collect()
    Config.installed_instance = True

if not Config.noPrompt and not Config.installed_instance:
    propertiesUtils.promptForProperties()

propertiesUtils.check_properties()

# initialize installers, order is important!
jreInstaller = JreInstaller()
jettyInstaller = JettyInstaller()
jythonInstaller = JythonInstaller()
rdbmInstaller = RDBMInstaller()
httpdinstaller = HttpdInstaller()
jansAuthInstaller = JansAuthInstaller()
configApiInstaller = ConfigApiInstaller()
jansCliInstaller = JansCliInstaller()


rdbmInstaller.packageUtils = packageUtils

if Config.installed_instance:
    for installer in (rdbmInstaller, httpdinstaller, jansAuthInstaller, configApiInstaller, jansCliInstaller):
        setattr(Config, installer.install_var, installer.installed())

    if not argsp.shell:
        propertiesUtils.promptForProperties()

        if not Config.addPostSetupService:
            print("No service was selected to install. Exiting ...")
            sys.exit()


def print_or_log(msg):
    print(msg) if argsp.x else base.logIt(msg)

app_vars = locals().copy()

if argsp.shell:
    code.interact(local=locals())
    sys.exit()

print()
print(jansInstaller)

proceed = True
if not Config.noPrompt:
    proceed_prompt = input('Proceed with these values [Y|n] ').lower().strip()
    if proceed_prompt and proceed_prompt[0] != 'y':
        proceed = False


# re-check packages
if proceed:
    packageUtils.check_and_install_packages()

# register post setup progress
class PostSetup:
    service_name = 'post-setup'
    install_var = 'installPostSetup'
    app_type = static.AppType.APPLICATION
    install_type = static.InstallOption.MONDATORY

jansProgress.register(PostSetup)

if not argsp.no_progress:
    jansProgress.queue = queue

def do_installation():
    jansProgress.before_start()
    jansProgress.start()

    try:
        jettyInstaller.calculate_selected_aplications_memory()

        if not Config.installed_instance:
            jansInstaller.configureSystem()
            jansInstaller.make_salt()
            jansAuthInstaller.make_salt()

            if not base.snap:
                jreInstaller.start_installation()
                jettyInstaller.start_installation()
                jythonInstaller.start_installation()

            jansInstaller.copy_scripts()

            jansInstaller.prepare_extension_scripts()
            jansInstaller.render_templates()

            jansInstaller.copy_output()
            jansInstaller.setup_init_scripts()

            # Installing jans components
            rdbmInstaller.dbUtils.read_jans_schema()
            rdbmInstaller.start_installation()

        if (Config.installed_instance and 'installHttpd' in Config.addPostSetupService) or (not Config.installed_instance and Config.installHttpd):
            httpdinstaller.configure()

        if (Config.installed_instance and 'installOxAuth' in Config.addPostSetupService) or (not Config.installed_instance and Config.installOxAuth):
            jansAuthInstaller.start_installation()

        if (Config.installed_instance and configApiInstaller.install_var in Config.addPostSetupService) or (not Config.installed_instance and Config.get(configApiInstaller.install_var)):
            configApiInstaller.start_installation()

        if Config.installJansCli:
            jansCliInstaller.start_installation()
            jansCliInstaller.configure()

        time.sleep(2)

        jansInstaller.post_install_tasks()

        for service in jansProgress.services:
            if service['app_type'] == static.AppType.SERVICE:
                jansProgress.progress(PostSetup.service_name,
                                      "Starting {}".format(service['name'].replace('-', ' ').replace('_', ' ').title()))
                time.sleep(2)
                service['object'].stop()
                service['object'].start()

        jansProgress.progress(static.COMPLETED)

        print()
        for m in Config.post_messages:
            print(m)

    except:

        base.logIt("FATAL", True, True)


if proceed:
    do_installation()
    print('\n', static.colors.OKGREEN)
    if Config.installConfigApi or Config.installScimServer:
        msg.installation_completed += "CLI available to manage Jannsen Server:\n"
        if Config.installConfigApi:
            msg.installation_completed += "/opt/jans/jans-cli/config-cli.py\n"

    msg_text = msg.post_installation if Config.installed_instance else msg.installation_completed.format(Config.hostname)
    print(msg_text)
    print('\n', static.colors.ENDC)
    # we need this for progress write last line
    time.sleep(2)
