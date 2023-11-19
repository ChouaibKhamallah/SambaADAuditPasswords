#!/usr/bin/python
# -*- coding: utf-8 -*-
import getpass
import ldb
import optparse
import samba.getopt as options
import requests
import time
import json
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

## CONF.INI PARAMETERS
configfile='/opt/SambaADAuditPasswords/conf.ini'
config = configparser.ConfigParser()
config.read(configfile)
dry_run = config.getboolean('common', 'dry_run')
anonymize_results = config.getboolean('common', 'anonymize_results')
if anonymize_results:
    print(colored("ANONYMIZED RESULTS\n","red"))
if dry_run:
    print(colored("DRYRUN - no users will be added to or deleted from the leaked_passwords_group_name group, only print","blue"))
check_duplicate_passwords = config.getboolean('common', 'check_duplicate_passwords')
check_leaked_passwords = config.getboolean('common', 'check_leaked_passwords')
smbconf=config.get('common', 'smbconf')
if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
    leaked_password_group = config.get('common', 'leaked_passwords_group_name')
if config.has_option('common','users_basedn'):
    users_basedn=config.get('common', 'users_basedn')
else:
    users_basedn = samdb.get_default_basedn() 
if config.getboolean('common', 'check_inactive_accounts'):
    user_filter = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))"
else:
    user_filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
## CONF.INI PARAMETERS
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
dict_hash = {}
anonymous_users_dict = {}
samba_ad_users_with_leaked_password_group = []
current_users_with_leaked_password = []
user_to_add_in_leaked_password_group = []
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
def ad_group_managment(group_name=None):
    global samba_ad_users_with_leaked_password_group
    query = (f"(sAMAccountName={group_name})")
    if not samdb.search(samdb.get_default_basedn(), expression=(f"(sAMAccountName={group_name})"), scope=ldb.SCOPE_SUBTREE):
        print(colored(f"\n\nAdd AD Group : {group_name}\n\n","green"))
        if not dry_run:
            samdb.newgroup(groupname=group_name)
    else:
        for group in samdb.search(samdb.get_default_basedn(), expression=(f"(sAMAccountName={group_name})"), scope=ldb.SCOPE_SUBTREE):
            if 'member' in group:
                samba_ad_users_with_leaked_password_group = [str(user).split("=")[1].split(",")[0] for user in group['member']]
            else:
                samba_ad_users_with_leaked_password_group = []
def create_dict_hash():
    user_nb = 0
    for user in samdb.search(base=users_basedn, expression=user_filter):
        Random.atfork()
        passwordattr = 'unicodePwd'
        password = testpawd.get_account_attributes(samdb,None,samdb.get_default_basedn(),filter="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
        if not passwordattr in password:
            continue
        hashnt = password[passwordattr][0].hex().upper()
        if hashnt in dict_hash:
            dict_hash[hashnt].append(user['samAccountName'][0].decode('utf-8'))
        else:
            dict_hash[hashnt] = [user['samAccountName'][0].decode('utf-8')]
        if anonymize_results:
            user_nb+=1
            dict_hash[hashnt][dict_hash[hashnt].index(user['samAccountName'][0].decode('utf-8'))] = str(user['samAccountName'][0].decode('utf-8')).replace(str(user['samAccountName'][0].decode('utf-8')),f"anonymous_{str(user_nb)}")
            anonymous_users_dict[str(user['samAccountName'][0].decode('utf-8')).replace(str(user['samAccountName'][0].decode('utf-8')),f"anonymous_{str(user_nb)}")] = anonymous_users_dict.get(str(user['samAccountName'][0].decode('utf-8')).replace(str(user['samAccountName'][0].decode('utf-8')),f"anonymous_{str(user_nb)}"),{})
            anonymous_users_dict[str(user['samAccountName'][0].decode('utf-8')).replace(str(user['samAccountName'][0].decode('utf-8')),f"anonymous_{str(user_nb)}")] = user['samAccountName'][0].decode('utf-8')
def run_check_duplicate_passwords(dict_hash=None):
    print(f"{'='*3} USERS WITH SAME PASSWORD CHECKING {'='*3}\n")
    datas = []
    group_nb = 0
    for entry in dict_hash:
        if len(dict_hash[entry]) >1:
            group_nb+=1
            datas.append([group_nb,len(dict_hash[entry]),dict_hash[entry][:10]])
    print(tabulate(datas, headers=["Group", "Number of accounts", "Accounts"]))
def run_check_leaked_passwords(dict_hash=None):
    print(f"\n{'='*3} LEAKED NTLM HASH CHECKING {'='*3}\n")
    print("Leaked base modification date : %s\n" % (requests.get("https://haveibeenpwned.com/api/v3/latestbreach").json()["ModifiedDate"].split("T")[0]))
    print(f"Please wait... {len(dict_hash)} hash to check\n")
    datas = []
    found = 0
    start_time = time.time()
    for nthash in dict_hash:
        percentage = int(list(dict_hash).index(nthash) / len(dict_hash) * 100)
        progress(percent=percentage, width=40,found=found,time_elasped=int(time.time()-start_time))
        result = requests.get(f"https://api.pwnedpasswords.com/range/{nthash[:5]}?mode=ntlm")
        resultihb = {h.split(':')[0]:h.split(':')[1] for h in  result.content.decode('utf-8').split('\r\n')}
        if nthash[5:] in resultihb:
            if anonymize_results:
                datas.append([nthash.replace(nthash,"#"*len(nthash)),resultihb[nthash[5:]],dict_hash[nthash]])
            else:
                datas.append([nthash,resultihb[nthash[5:]],dict_hash[nthash]])
            found+=1
            if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
                for user in dict_hash[nthash]:
                    if not anonymize_results:
                        if not user in samba_ad_users_with_leaked_password_group:
                            user_to_add_in_leaked_password_group.append(user)
                        if not user in current_users_with_leaked_password:
                            current_users_with_leaked_password.append(user)
                    else:
                        if not anonymous_users_dict[user] in samba_ad_users_with_leaked_password_group:
                            user_to_add_in_leaked_password_group.append(user)
                        if not user in current_users_with_leaked_password:
                            current_users_with_leaked_password.append(user)
    print("\n")
    print(tabulate(datas, headers=["Hashnt", "Number of leaks", "Accounts"]))
def add_remove_users_ad_group(anonymize_results):
    print(f"\n{'='*3} LEAKED AD GROUP MODIFICATIONS CHECKING {'='*3}\n")
    if not anonymize_results:
        user_to_delete_from_leaked_password_group = list(set(samba_ad_users_with_leaked_password_group).difference(set(current_users_with_leaked_password)))
       
        print(f"user_to_add_in_leaked_group {user_to_add_in_leaked_password_group}")
        if not dry_run:
            samdb.add_remove_group_members(groupname=leaked_password_group, members=user_to_add_in_leaked_password_group, add_members_operation=True)
        print(f"user_to_delete_from_leaked_group {user_to_delete_from_leaked_password_group}")
        if not dry_run:
            samdb.add_remove_group_members(groupname=leaked_password_group, members=user_to_delete_from_leaked_password_group, add_members_operation=False)
    else:
        anonymized_current_users_with_leaked_password = []
        for user in current_users_with_leaked_password:
            anonymized_current_users_with_leaked_password.append(anonymous_users_dict[user])
        user_to_delete_from_leaked_password_group = list(set(samba_ad_users_with_leaked_password_group).difference(set(anonymized_current_users_with_leaked_password)))
        decrypt_user_to_add_in_leaked_password_group = []
        for user in user_to_add_in_leaked_password_group:
            decrypt_user_to_add_in_leaked_password_group.append(anonymous_users_dict[user])
        print(f"user_to_add_in_leaked_group : {len(decrypt_user_to_add_in_leaked_password_group)} anonymised_users")
        if not dry_run:
            samdb.add_remove_group_members(groupname=leaked_password_group, members=decrypt_user_to_add_in_leaked_password_group, add_members_operation=True)
        print(f"user_to_delete_from_leaked_group : {len(user_to_delete_from_leaked_password_group)} anonymised_users")
        if not dry_run:
            samdb.add_remove_group_members(groupname=leaked_password_group, members=user_to_delete_from_leaked_password_group, add_members_operation=False)
def audit_passwords():
    if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
        ad_group_managment(group_name=leaked_password_group)
    create_dict_hash()
    if check_duplicate_passwords:
        run_check_duplicate_passwords(dict_hash=dict_hash)
    if check_leaked_passwords:
        run_check_leaked_passwords(dict_hash=dict_hash)
        if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
            add_remove_users_ad_group(anonymize_results)
    print('\n')
if __name__ == '__main__':
    audit_passwords()