import warnings
import sys
import os
import re
import json
import logging
import copy
import ldap3
import pymysql
from ldap3.utils import dn as dnutils
from pathlib import PurePath

warnings.filterwarnings("ignore")

from setup_app import static
from setup_app.config import Config
from setup_app.static import InstallTypes, BackendTypes, colors
from setup_app.utils import base
from setup_app.utils import ldif_utils
from setup_app.utils.attributes import attribDataTypes

my_path = PurePath(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(my_path.parent.joinpath('pylib/sqlalchemy'))


import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.automap


class DBUtils:

    processedKeys = []
    Base = None
    session = None

    def bind(self, use_ssl=True, force=False):

        if not self.session or force:
            base.logIt("Making MySql Conncetion")
            result = self.mysqlconnection()
            if not result[0]:
                print("{}FATAL: {}{}".format(colors.FAIL, result[1], colors.ENDC))

    def sqlconnection(self, log=True):
        base.logIt("Making {} Connection to {}:{}/{} with user {}".format(Config.rdbm_type.upper(), Config.rdbm_host, Config.rdbm_port, Config.rdbm_db, Config.rdbm_user))

        db_str = 'mysql+pymysql' if Config.rdbm_type == 'mysql' else 'postgresql+psycopg2'

        bind_uri = '{}://{}:{}@{}:{}/{}'.format(
                        db_str,
                        Config.rdbm_user,
                        Config.rdbm_password,
                        Config.rdbm_host,
                        Config.rdbm_port,
                        Config.rdbm_db,
                )

        if Config.rdbm_type == 'mysql':
            bind_uri += '?charset=utf8mb4'

        try:
            self.engine = sqlalchemy.create_engine(bind_uri)
            logging.basicConfig(filename=os.path.join(Config.install_dir, 'logs/sqlalchemy.log'))
            logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
            Session = sqlalchemy.orm.sessionmaker(bind=self.engine)
            self.session = Session()
            self.metadata = sqlalchemy.MetaData()
            self.session.connection()
            base.logIt("{} Connection was successful".format(Config.rdbm_type.upper()))
            return True, self.session

        except Exception as e:
            if log:
                base.logIt("Can't connect to {} server: {}".format(Config.rdbm_type.upper(), str(e), True))
            return False, e

    @property
    def json_dialects_instance(self):
        return sqlalchemy.dialects.mysql.json.JSON if Config.rdbm_type == 'mysql' else sqlalchemy.dialects.postgresql.json.JSON
        
    def mysqlconnection(self, log=True):
        return self.sqlconnection(log)

    def read_jans_schema(self, others=[]):
        base.logIt("Reading jans schema")

        self.jans_attributes = []

        for schema_fn_ in ['jans_schema.json', 'custom_schema.json'] + others:
            schema_fn = schema_fn_ if schema_fn_.startswith('/') else os.path.join(Config.install_dir, 'schema', schema_fn_)
            schema = base.readJsonFile(schema_fn)
            self.jans_attributes += schema['attributeTypes']

        self.ldap_sql_data_type_mapping = base.readJsonFile(os.path.join(Config.static_rdbm_dir, 'ldap_sql_data_type_mapping.json'))
        self.sql_data_types = base.readJsonFile(os.path.join(Config.static_rdbm_dir, 'sql_data_types.json'))
        self.opendj_attributes_syntax = base.readJsonFile(os.path.join(Config.static_rdbm_dir, 'opendj_attributes_syntax.json'))


    def exec_rdbm_query(self, query, getresult=False):
        base.logIt("Executing {} Query: {}".format(Config.rdbm_type, query))
        if Config.rdbm_type in ('mysql', 'pgsql'):
            try:
                qresult = self.session.execute(query)
                self.session.commit()
            except Exception as e:
                base.logIt("ERROR executing query {}".format(e.args))
                base.logIt("ERROR executing query {}".format(e.args), True)
            else:
                if getresult == 1:
                    return qresult.first()
                elif getresult:
                    return qresult.fetchall()

    def get_oxAuthConfDynamic(self):

        result = self.search(search_base='ou=jans-auth,ou=configuration,o=jans', search_filter='(objectClass=jansAppConf)', search_scope=ldap3.BASE)
        dn = result['dn'] 
        oxAuthConfDynamic = json.loads(result['jansConfDyn'])

        return dn, oxAuthConfDynamic


    def set_oxAuthConfDynamic(self, entries):

        dn, oxAuthConfDynamic = self.get_oxAuthConfDynamic()
        oxAuthConfDynamic.update(entries)
        sqlalchemyObj = self.get_sqlalchObj_for_dn(dn)
        sqlalchemyObj.jansConfDyn = json.dumps(oxAuthConfDynamic, indent=2)
        self.session.commit()


    def enable_script(self, inum):
        dn = 'inum={},ou=scripts,o=jans'.format(inum)
        sqlalchemyObj = self.get_sqlalchObj_for_dn(dn)
        sqlalchemyObj.jansEnabled = 1
        self.session.commit()


    def enable_service(self, service):
        sqlalchemyObj = self.get_sqlalchObj_for_dn('ou=configuration,o=jans')
        setattr(sqlalchemyObj, service, 1)
        self.session.commit()


    def set_configuration(self, component, value):

        result = self.get_sqlalchObj_for_dn('ou=configuration,o=jans')
        table_name = result.objectClass
        sqlalchemy_table = self.Base.classes[table_name]
        sqlalchemyObj = self.session.query(sqlalchemy_table).filter(sqlalchemy_table.dn =='ou=configuration,o=jans').first()
        cur_val = getattr(sqlalchemyObj, component)
        setattr(sqlalchemyObj, component, value)
        self.session.commit()


    def dn_exists(self, dn):
        base.logIt("Querying RDBM for dn {}".format(dn))
        result = self.get_sqlalchObj_for_dn(dn)
        if result:
            return result.__dict__
        return

    def dn_exists_rdbm(self, dn, table):
        base.logIt("Checking dn {} exists in table {}".format(dn, table))
        sqlalchemy_table = self.Base.classes[table].__table__
        return self.session.query(sqlalchemy_table).filter(sqlalchemy_table).filter(sqlalchemy_table.columns.dn == dn).first()

    def search(self, search_base, search_filter='(objectClass=*)', search_scope=ldap3.LEVEL, fetchmany=False):
        base.logIt("Searching database for dn {} with filter {}".format(search_base, search_filter))

        if self.Base is None:
            self.rdm_automapper()

        s_table = None
        where_clause = ''
        search_list = []

        if '&' in search_filter:
            re_match = re.match('\(&\((.*?)=(.*?)\)\((.*?)=(.*?)\)', search_filter)
            if re_match:
                re_list = re_match.groups()
                search_list.append((re_list[0], re_list[1]))
                search_list.append((re_list[2], re_list[3]))
        else:
            re_match = re.match('\((.*?)=(.*?)\)', search_filter)

            if re_match:
                re_list = re_match.groups()
                search_list.append((re_list[0], re_list[1]))


        for col, val in search_list:
            if col.lower() == 'objectclass':
                s_table = val
                break

        if not s_table:
            return

        sqlalchemy_table = self.Base.classes[s_table]
        sqlalchemyQueryObject = self.session.query(sqlalchemy_table)

        for col, val in search_list:
            if val == '*':
                continue

            if col.lower() != 'objectclass':
                val = val.replace('*', '%')
                sqlalchemyCol = getattr(sqlalchemy_table, col)
                if '%' in val:
                    sqlalchemyQueryObject = sqlalchemyQueryObject.filter(sqlalchemyCol.like(val))
                else:
                    sqlalchemyQueryObject = sqlalchemyQueryObject.filter(sqlalchemyCol == val)

    def add2strlist(self, client_id, strlist):
        value2 = []
        for v in strlist.split(','):
            if v.strip():
                value2.append(v.strip())
        value2.append(client_id)

        return  ','.join(value2)

    def add_client2script(self, script_inum, client_id):
        dn = 'inum={},ou=scripts,o=jans'.format(script_inum)

        sqlalchemyObj = self.get_sqlalchObj_for_dn(dn)
        if sqlalchemyObj:
            if sqlalchemyObj.jansConfProperty:
                jansConfProperty = copy.deepcopy(sqlalchemyObj.jansConfProperty)
            else:
                jansConfProperty = {'v': []}

            for oxconfigprop in jansConfProperty['v']:
                if oxconfigprop.get('value1') == 'allowed_clients' and not client_id in oxconfigprop['value2']:
                    oxconfigprop['value2'] = self.add2strlist(client_id, oxconfigprop['value2'])
                    break
            else:
                jansConfProperty['v'].append({'value1': 'allowed_clients', 'value2': client_id})

            sqlalchemyObj.jansConfProperty = jansConfProperty                
            self.session.commit()


    def get_key_prefix(self, key):
        n = key.find('_')
        return key[:n+1]

    def get_attr_syntax(self, attrname):
        for jans_attr in self.jans_attributes:
            if attrname in jans_attr['names']:
                if jans_attr.get('multivalued'):
                    return 'JSON'
                return jans_attr['syntax']
        else:
            opendj_syntax = self.opendj_attributes_syntax.get(attrname)
            if opendj_syntax is None:
                opendj_syntax = '1.3.6.1.4.1.1466.115.121.1.15'

            return opendj_syntax

    def get_rootdn(self, dn):
        dn_parsed = dnutils.parse_dn(dn)
        dn_parsed.pop(0)
        dnl=[]

        for dnp in dn_parsed:
            dnl.append('='.join(dnp[:2]))

        return ','.join(dnl)


    def rdm_automapper(self, force=False):
        if not force and self.Base:
            return

        base.logIt("Reflecting ORM tables")

        self.metadata.reflect(self.engine)
        self.Base = sqlalchemy.ext.automap.automap_base(metadata=self.metadata)
        self.Base.prepare()

        base.logIt("Reflected tables {}".format(list(self.metadata.tables.keys())))

    def get_sqlalchObj_for_dn(self, dn):

        for tbl in self.Base.classes:
            result = self.session.query(tbl).filter(tbl.dn == dn).first()
            if result:
                return result

        for tbl in self.Base.classes:
            result = self.session.query(tbl).filter(tbl.dn.like('%'+dn)).first()
            if result:
                return result

    def table_exists(self, table):
        metadata = sqlalchemy.MetaData()
        try:
            metadata.reflect(self.engine, only=[table])
        except:
            pass

        return table in metadata

    def get_attr_sql_data_type(self, key):
        if key in self.sql_data_types:
            data_type = self.sql_data_types[key]
        else:
            attr_syntax = self.get_attr_syntax(key)
            data_type = self.ldap_sql_data_type_mapping[attr_syntax]
    
        data_type = (data_type.get(Config.rdbm_type) or data_type['mysql'])['type']

        return data_type

    def get_rdbm_val(self, key, val):
        
        data_type = self.get_attr_sql_data_type(key)

        if data_type in ('SMALLINT',):
            if val[0].lower() in ('1', 'on', 'true', 'yes', 'ok'):
                return 1
            return 0

        if data_type == 'INT':
            return int(val[0])

        if data_type in ('DATETIME(3)', 'TIMESTAMP'):
            dval = val[0].strip('Z')
            return "{}-{}-{} {}:{}:{}{}".format(dval[0:4], dval[4:6], dval[6:8], dval[8:10], dval[10:12], dval[12:14], dval[14:17])

        if data_type == 'JSON':
            json_data = {'v':[]}
            for d in val:
                json_data['v'].append(d)

            return json_data

        return val[0]


    def import_ldif(self, ldif_files, bucket=None, force=None):

        base.logIt("Importing ldif file(s): {} ".format(', '.join(ldif_files)))

        sql_data_fn = os.path.join(Config.outputFolder, Config.rdbm_type, 'jans_data.sql')

        for ldif_fn in ldif_files:
            base.logIt("Importing entries from " + ldif_fn)
            parser = ldif_utils.myLdifParser(ldif_fn)
            parser.parse()

            for dn, entry in parser.entries:
                if self.Base is None:
                    self.rdm_automapper()

                if 'add' in  entry and 'changetype' in entry:
                    attribute = entry['add'][0]
                    new_val = entry[attribute]
                    sqlalchObj = self.get_sqlalchObj_for_dn(dn)

                    if sqlalchObj:
                        if isinstance(sqlalchObj.__table__.columns[attribute].type, self.json_dialects_instance):
                            cur_val = copy.deepcopy(getattr(sqlalchObj, attribute))
                            for val_ in new_val:
                                cur_val['v'].append(val_)
                            setattr(sqlalchObj, attribute, cur_val)
                        else:
                            setattr(sqlalchObj, attribute, new_val[0])

                        self.session.commit()

                    else:
                        base.logIt("Can't find current value for repmacement of {}".replace(str(entry)), True)
                        continue

                elif 'replace' in entry and 'changetype' in entry:
                    attribute = entry['replace'][0]
                    new_val = self.get_rdbm_val(attribute, entry[attribute])
                    sqlalchObj = self.get_sqlalchObj_for_dn(dn)

                    if sqlalchObj:
                        setattr(sqlalchObj, attribute, new_val)
                        self.session.commit()
                    else:
                        base.logIt("Can't find current value for repmacement of {}".replace(str(entry)), True)
                        continue

                else:
                    vals = {}
                    dn_parsed = dnutils.parse_dn(dn)
                    rdn_name = dn_parsed[0][0]
                    objectClass = entry.get('objectClass') or entry.get('objectclass')

                    if objectClass:
                        if 'top' in objectClass:
                            objectClass.remove('top')
                        if  len(objectClass) == 1 and objectClass[0].lower() == 'organizationalunit':
                            continue
                        objectClass = objectClass[-1]

                    vals['doc_id'] = dn_parsed[0][1]
                    vals['dn'] = dn
                    vals['objectClass'] = objectClass

                    #entry.pop(rdn_name)
                    if 'objectClass' in entry:
                        entry.pop('objectClass')
                    elif 'objectclass' in entry:
                        entry.pop('objectclass')

                    table_name = objectClass

                    if self.dn_exists_rdbm(dn, table_name):
                        base.logIt("DN {} exsits in {} skipping".format(dn, Config.rdbm_type))
                        continue

                    for lkey in entry:
                        vals[lkey] = self.get_rdbm_val(lkey, entry[lkey])

                    sqlalchCls = self.Base.classes[table_name]

                    for col in sqlalchCls.__table__.columns:
                        if isinstance(col.type, self.json_dialects_instance) and not col.name in vals:
                            vals[col.name] = {'v': []}

                    sqlalchObj = sqlalchCls()

                    for v in vals:
                        setattr(sqlalchObj, v, vals[v])

                    base.logIt("Adding {}".format(sqlalchObj.doc_id))
                    self.session.add(sqlalchObj)
                    self.session.commit()


    def get_group_for_key(self, key):
        key_prefix = self.get_key_prefix(key)
        for group in Config.couchbaseBucketDict:
            if key_prefix in Config.couchbaseBucketDict[group]['document_key_prefix']:
                break
        else:
            group = 'default'

        return group


    def __del__(self):
        # TODO: close sql connection
        return

dbUtils = DBUtils()
dbUtils.read_jans_schema()
