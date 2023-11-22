#!/usr/bin/python
# -*- coding: utf-8 -*-
import getpass
import ldb
import optparse
import samba.getopt as options
import requests
import time
import json
from os import path
import configparser
from colorama import init
from termcolor import colored
from tabulate import tabulate
from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.dcerpc.security import dom_sid
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand
from Cryptodome import Random

configfile='/opt/SambaADAuditPasswords/conf.ini'
config = configparser.ConfigParser()
config.read(configfile)
smbconf=config.get('common', 'smbconf')
# SAMBA AD BASE CONNECTION
parser = optparse.OptionParser(smbconf)
sambaopts = options.SambaOptions(parser)
lp = sambaopts.get_loadparm()
creds = Credentials()
creds.guess(lp)
samdb = SamDB( session_info=system_session(),credentials=creds, lp=lp)
testpawd = GetPasswordCommand()
testpawd.lp = lp
# SAMBA AD BASE CONNECTION

## CONF.INI PARAMETERS

dry_run = config.getboolean('common', 'dry_run')
anonymize_results = config.getboolean('common', 'anonymize_results')

if anonymize_results:
    print(colored("ANONYMIZED RESULTS\n","red"))
if dry_run:
    print(colored("DRYRUN - no users will be added to or deleted from the leaked_passwords_group_name group, only print","blue"))

check_duplicate_passwords = config.getboolean('common', 'check_duplicate_passwords')

check_leaked_passwords = config.getboolean('common', 'check_leaked_passwords')



if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
    leaked_password_group = config.get('common', 'leaked_passwords_group_name')
 
if config.getboolean('common', 'check_inactive_accounts'):
    user_filter = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))"
else:
    user_filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

if config.has_option("common","local_json"):
    dict_hash_status = {}
    if path.isfile(config.get('common','local_json')):
        dict_hash_status = json.load(open(config.get('common','local_json'),"r"))

if config.has_option('common','users_basedn'):
    users_basedn=config.get('common', 'users_basedn')
    print(colored(f'Filtering results in {users_basedn}','green'))
else:
    users_basedn = samdb.get_default_basedn()

## CONF.INI PARAMETERS

dict_hash = {}
users_dict = {}
samba_ad_users_with_leaked_password_group = []
current_users_with_leaked_password = []
user_to_add_in_leaked_password_group = []
privilegied_accounts = []

# FUNCTION TO PRINT PROGRESS BAR
def progress(percent=0, width=40,found=0,time_elasped=0):
    left = width * percent // 100
    right = width - left
    tags = "#" * left
    spaces = " " * right
    percents = f"{percent:.0f}%"
    time_elasped = f"{int(time_elasped)}s"
    if found > 0:
        found = colored(found,'red')
    print("\r[", colored(tags,'green'), spaces, "]", f" Task status : {percents} - Time elapsed : {time_elasped} - Founded leaked hash : {found}",  sep="", end="", flush=True)

def add_to_list_if_user_member(groupname=None,group_list=None,sAMAccountName=None,user_memberof=None):

    memberOf = [str(group).split("=")[1].split(",")[0] for group in user_memberof if str(group).split("=")[1].split(",")[0] == groupname]
    if memberOf != []:
        if sAMAccountName not in group_list:
            group_list.append(sAMAccountName)

def create_dict_hash():

    user_nb = 0
    for user in samdb.search(base=samdb.get_default_basedn(), expression=user_filter):
        user_nb+=1

        sAMAccountName = user['samAccountName'][0].decode('utf-8')
        Anon_sAMAccountName = str(user['samAccountName'][0].decode('utf-8')).replace(str(user['samAccountName'][0].decode('utf-8')),f"anonymous_{str(user_nb)}")
        
        if 'memberOf' in user:
            if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
                add_to_list_if_user_member(groupname=leaked_password_group,group_list=samba_ad_users_with_leaked_password_group,sAMAccountName=sAMAccountName,user_memberof=user['memberOf'])
        
            if config.getboolean('common','check_privilegied_group'):
                if config.has_option('common','privilegied_groups'):
                    for group in config.get('common','privilegied_groups').split(','):
                        add_to_list_if_user_member(groupname=group,group_list=privilegied_accounts,sAMAccountName=sAMAccountName,user_memberof=user['memberOf'])

        if str(users_basedn) in user['distinguishedName'][0].decode('utf-8'):

            Random.atfork()
            passwordattr = 'unicodePwd'
            password = testpawd.get_account_attributes(samdb,None,samdb.get_default_basedn(),filter="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
            if not passwordattr in password:
                continue
            hashnt = password[passwordattr][0].hex().upper()
            
            if config.getboolean('common','check_privilegied_group'):
                dict_hash[hashnt] = dict_hash.get(hashnt,{'accounts':[],'anon_accounts':[],'privilegied_accounts':[]})
                if sAMAccountName in privilegied_accounts:
                    dict_hash[hashnt]['privilegied_accounts'].append(sAMAccountName)
            else:
                dict_hash[hashnt] = dict_hash.get(hashnt,{'accounts':[],'anon_accounts':[]})

            dict_hash[hashnt]['anon_accounts'].append(Anon_sAMAccountName)
            dict_hash[hashnt]['accounts'].append(user['samAccountName'][0].decode('utf-8'))
            
            users_dict[sAMAccountName] = Anon_sAMAccountName

def run_check_duplicate_passwords(dict_hash=None):

    print(f"{'='*3} USERS WITH SAME PASSWORD CHECKING {'='*3}\n")
    datas = []

    for entry in dict_hash:
        if len(dict_hash[entry]['accounts']) > 1:
            if anonymize_results:
                if config.getboolean('common','check_privilegied_group'):
                    datas.append([len(dict_hash[entry]['accounts']),len(dict_hash[entry]['privilegied_accounts']),dict_hash[entry]['anon_accounts'][:3]])
                else:
                    datas.append([len(dict_hash[entry]['accounts']),dict_hash[entry]['anon_accounts'][:3]])
            else:
                if config.getboolean('common','check_privilegied_group'):
                    datas.append([len(dict_hash[entry]['accounts']),len(dict_hash[entry]['privilegied_accounts']),dict_hash[entry]['accounts'][:3]])
                else:
                    datas.append([len(dict_hash[entry]['accounts']),dict_hash[entry]['accounts'][:3]])

    if config.getboolean('common','check_privilegied_group'):
        print(tabulate(datas, headers=["Number of accounts","Privilegied accounts","Accounts"]))

        print(f"\n{'='*3} CHECKING FOR DUPLICATED HASH FOR PRIVILEGIED ACCOUNTS {'='*3}\n")
        for entry in dict_hash:
            if len(dict_hash[entry]['accounts']) > 1:
                if len(dict_hash[entry]['privilegied_accounts']) > 0:
                    for user in dict_hash[entry]['privilegied_accounts']:
                        if anonymize_results:
                            user = users_dict[user]
                        print(f'WARNING: {entry} is used by {len(dict_hash[entry]["accounts"])} users, including privilegied account : {user}')
    else:
        print(tabulate(datas, headers=["Number of accounts","Accounts"]))

def check_online(nthash):

    leaked = False
    result = requests.get(f"https://api.pwnedpasswords.com/range/{nthash[:5]}?mode=ntlm")
    resultihb = {h.split(':')[0]:h.split(':')[1] for h in  result.content.decode('utf-8').split('\r\n')}
    if nthash[5:] in resultihb:
        dict_hash_status['hash_status'][nthash] = dict_hash_status['hash_status'].get(nthash,{'leaked':True,'leaked_nb':resultihb[nthash[5:]]})
        leaked = True
    
    return leaked

def make_full_rescan_after_api_date_modification():

    full_rescan = False
    if requests.get("https://haveibeenpwned.com/api/v3/latestbreach").json()["ModifiedDate"].split("T")[0] != dict_hash_status.get('last_scan_api_modification_date',''):
        full_rescan = True
    
    return full_rescan

def export_results_to_cache_file():

    with open(config.get('common','local_json'), "w+",encoding = 'utf-8') as outfile:
        outfile.write(json.dumps(dict_hash_status, indent=4))

def run_check_leaked_passwords(dict_hash=None):

    print(f"\n{'='*3} LEAKED NTLM HASH CHECKING {'='*3}\n")

    print("Leaked base modification date : %s\n" % (requests.get("https://haveibeenpwned.com/api/v3/latestbreach").json()["ModifiedDate"].split("T")[0]))
    print(f"Please wait... {len(dict_hash)} hash to check\n")
    
    full_rescan = make_full_rescan_after_api_date_modification()
    if not full_rescan:
        dict_hash_status['hash_status'] = dict_hash_status.get('hash_status',{})
    else:
         dict_hash_status['hash_status'] = {}

    dict_hash_status["last_scan_api_modification_date"] = dict_hash_status.get('last_scan_api_modification_date',requests.get("https://haveibeenpwned.com/api/v3/latestbreach").json()["ModifiedDate"].split("T")[0])

    datas = []
    found = 0
    start_time = time.time()

    for nthash in dict_hash:
        leaked = False
        percentage = int(list(dict_hash).index(nthash) / len(dict_hash) * 100)
        progress(percent=percentage, width=40,found=found,time_elasped=int(time.time()-start_time))
        if not full_rescan:
            if nthash in dict_hash_status['hash_status']:
                if dict_hash_status['hash_status'][nthash]["leaked"]:
                    dict_hash_status['hash_status'][nthash].update({'leaked':True,'leaked_nb':dict_hash_status['hash_status'][nthash]['leaked_nb']})
                    leaked = True
            else:
                if check_online(nthash):
                    leaked = True
        else:
            if check_online(nthash):
                leaked = True
        if leaked:
            for user in dict_hash[nthash]['accounts']:
                current_users_with_leaked_password.append(user)
                if not user in samba_ad_users_with_leaked_password_group:
                    user_to_add_in_leaked_password_group.append(user)
            if anonymize_results:
                datas.append([nthash.replace(nthash,"#"*len(nthash)),dict_hash_status['hash_status'][nthash]['leaked_nb'],dict_hash[nthash]['anon_accounts']])
            else:
                datas.append([nthash,dict_hash_status['hash_status'][nthash]['leaked_nb'],dict_hash[nthash]['accounts']])
            found+=1
        else:
            dict_hash_status['hash_status'][nthash] = dict_hash_status['hash_status'].get(nthash,{'leaked':False,'leaked_nb':0})
    print("\n")
    print(tabulate(datas, headers=["Hashnt", "Number of leaks", "Accounts"]))

    if config.getboolean('common','check_privilegied_group'):
        print(f"\n{'='*3} CHECKING FOR LEAKED HASH FOR PRIVILEGIED ACCOUNTS {'='*3}\n")
        for user in current_users_with_leaked_password:
            if user in privilegied_accounts:
                if anonymize_results:
                    user = users_dict[user]
                print(f'WARNING: NTHASH for {user}') 

def add_remove_users_ad_group():
    print(f"\n{'='*3} LEAKED AD GROUP MODIFICATIONS CHECKING {'='*3}\n")
    user_to_delete_from_leaked_password_group = list(set(samba_ad_users_with_leaked_password_group).difference(set(current_users_with_leaked_password)))

    if anonymize_results:
        print(f"user_to_add_in_leaked_group {[users_dict[x] for x in user_to_add_in_leaked_password_group]}")
        print(f"user_to_delete_from_leaked_group {[users_dict[x] for x in user_to_delete_from_leaked_password_group]}")
    else:
        print(f"user_to_add_in_leaked_group {user_to_add_in_leaked_password_group}")
        print(f"user_to_delete_from_leaked_group {user_to_delete_from_leaked_password_group}")

    if not dry_run:
        samdb.add_remove_group_members(groupname=leaked_password_group, members=user_to_add_in_leaked_password_group, add_members_operation=True)
        samdb.add_remove_group_members(groupname=leaked_password_group, members=user_to_delete_from_leaked_password_group, add_members_operation=False)

def audit_passwords():

    create_dict_hash()
    if check_duplicate_passwords:
        run_check_duplicate_passwords(dict_hash=dict_hash)
    if check_leaked_passwords:
        run_check_leaked_passwords(dict_hash=dict_hash)
        if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
            add_remove_users_ad_group()
    print('\n')

if __name__ == '__main__':
    audit_passwords()
