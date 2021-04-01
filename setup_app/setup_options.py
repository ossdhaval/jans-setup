import os
import sys
import argparse

from setup_app.static import InstallTypes
from setup_app.utils import base

def get_setup_options():

    setupOptions = {
        'setup_properties': None,
        'noPrompt': False,
        'downloadWars': False,
        'installOxAuth': True,
        'installConfigApi': True,
        'installHTTPD': True,
    }

    setupOptions['rdbm_install'] = True
    
    if base.argsp.local_rdbm:
        setupOptions['rdbm_type'] = base.argsp.local_rdbm
        setupOptions['rdbm_install_type'] = InstallTypes.LOCAL

    elif base.argsp.remote_rdbm:
        setupOptions['rdbm_type'] = base.argsp.remote_rdbm
        setupOptions['rdbm_install_type'] = InstallTypes.REMOTE

    setupOptions['rdbm_host'] = 'localhost'

    if base.argsp.rdbm_port:
        setupOptions['rdbm_port'] = base.argsp.rdbm_port
    else:
        if setupOptions.get('rdbm_type') == 'pgsql':
            setupOptions['rdbm_port'] = 5432

    if base.argsp.rdbm_db:
        setupOptions['rdbm_db'] = base.argsp.rdbm_db

    if base.argsp.rdbm_user:
        setupOptions['rdbm_user'] = base.argsp.rdbm_user

    if base.argsp.rdbm_password:
        setupOptions['rdbm_password'] = base.argsp.rdbm_password

    if base.argsp.ip_address:
        setupOptions['ip'] = base.argsp.ip_address

    if base.argsp.host_name:
        setupOptions['hostname'] = base.argsp.host_name
        
    if base.argsp.org_name:
        setupOptions['orgName'] = base.argsp.org_name

    if base.argsp.email:
        setupOptions['admin_email'] = base.argsp.email

    if base.argsp.city:
        setupOptions['city'] = base.argsp.city

    if base.argsp.state:
        setupOptions['state'] = base.argsp.state

    if base.argsp.country:
        setupOptions['countryCode'] = base.argsp.country

    if base.argsp.jans_max_mem:
        setupOptions['jans_max_mem'] = base.argsp.jans_max_mem

    setupOptions['noPrompt'] = base.argsp.n

    if base.argsp.no_httpd:
        setupOptions['installHTTPD'] = False

    if base.argsp.ob_key_fn:
        setupOptions['ob_key_fn'] = base.argsp.ob_key_fn

    if base.argsp.ob_cert_fn:
        setupOptions['ob_cert_fn'] = base.argsp.ob_cert_fn

    if base.argsp.ob_alias:
        setupOptions['ob_alias'] = base.argsp.ob_alias

    return setupOptions
