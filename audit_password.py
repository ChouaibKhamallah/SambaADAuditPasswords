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
import pandas as pd
from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.dcerpc.security import dom_sid
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand
from Cryptodome import Random
from datetime import datetime, timedelta

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
    user_filter = "(&(objectClass=user)(objectCategory=person))"
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
users_leak_dict = {}
samba_ad_users_with_leaked_password_group = []
current_users_with_leaked_password = []
user_to_add_in_leaked_password_group = []
privilegied_accounts = []
anonymous_privilegied_accounts = []

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

def create_ad_group_if_needed(group_name=None):
    query = (f"(sAMAccountName={group_name})")
    if not samdb.search(samdb.get_default_basedn(), expression=(f"(sAMAccountName={group_name})"), scope=ldb.SCOPE_SUBTREE):
        print(colored(f"\n\nAdd AD Group : {group_name}\n\n","green"))
        if not dry_run:
            samdb.newgroup(groupname=group_name)

def add_to_list_if_user_member(groupname=None,group_list=None,sAMAccountName=None,user_memberof=None):

    memberOf = [str(group).split("=")[1].split(",")[0] for group in user_memberof if str(group).split("=")[1].split(",")[0] == groupname]
    if memberOf != []:
        if not sAMAccountName in group_list:
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

            if sAMAccountName in privilegied_accounts and not Anon_sAMAccountName in anonymous_privilegied_accounts:
                anonymous_privilegied_accounts.append(Anon_sAMAccountName)
                
def run_check_duplicate_passwords(dict_hash=None):

    print(f"{'='*3} USERS WITH SAME PASSWORD CHECKING {'='*3}\n")
    datas = []

    for entry in dict_hash:
        if len(dict_hash[entry]['accounts']) > 1:
            if anonymize_results:
                if config.getboolean('common','check_privilegied_group'):
                    datas.append([len(dict_hash[entry]['accounts']),len(dict_hash[entry]['privilegied_accounts']),', '.join(dict_hash[entry]["anon_accounts"][:2]),f'and {len(dict_hash[entry]["anon_accounts"][2:])} more'])
                else:
                    datas.append([len(dict_hash[entry]['accounts']),', '.join(dict_hash[entry]["anon_accounts"][:2]),f'and {len(dict_hash[entry]["anon_accounts"][2:])} more'])
            else:
                if config.getboolean('common','check_privilegied_group'):
                    datas.append([len(dict_hash[entry]['accounts']),len(dict_hash[entry]['privilegied_accounts']),', '.join(dict_hash[entry]["accounts"][:2]),f'and {len(dict_hash[entry]["accounts"][2:])} more'])
                else:
                    datas.append([len(dict_hash[entry]['accounts']),', '.join(dict_hash[entry]["accounts"][:2]),f'and {len(dict_hash[entry]["accounts"][2:])} more'])

    if config.getboolean('common','check_privilegied_group'):
        print(tabulate(datas, headers=["Number of accounts","Privilegied accounts","Accounts","How much More ?"]))

        print(f"\n{'='*3} CHECKING FOR DUPLICATED HASH FOR PRIVILEGIED ACCOUNTS {'='*3}\n")
        for entry in dict_hash:
            duplicated_hash_for_privilegied_account = False
            if len(dict_hash[entry]['accounts']) > 1:
                if len(dict_hash[entry]['privilegied_accounts']) > 0:
                    for user in dict_hash[entry]['privilegied_accounts']:
                        duplicated_hash_for_privilegied_account = True
            if duplicated_hash_for_privilegied_account:
                if anonymize_results:                
                    print(f'WARNING: {"#"*len(entry)} is used by {len(dict_hash[entry]["accounts"])} users, including privilegied account : {", " .join([x for x in dict_hash[entry]["anon_accounts"] if x in anonymous_privilegied_accounts])}')
                else:
                    print(f'WARNING: {entry} is used by {len(dict_hash[entry]["accounts"])} users, including privilegied account : {", ".join([x for x in dict_hash[entry]["accounts"] if x in privilegied_accounts])}')
    else:
        print(tabulate(datas, headers=["Number of accounts","Accounts","How much More ?"]))

def check_nthash_online_if_needed(nthash):

    leaked = False
    dict_hash_status['hash_status'][nthash[:5]] = dict_hash_status['hash_status'].get(nthash[:5],{})
    result = requests.get(f"https://api.pwnedpasswords.com/range/{nthash[:5]}?mode=ntlm")
    resultihb = {h.split(':')[0]:h.split(':')[1] for h in  result.content.decode('utf-8').split('\r\n')}
    if nthash[5:] in resultihb:
        dict_hash_status['hash_status'][nthash[:5]].update({nthash[5:]:int(resultihb[nthash[5:]])})
        leaked = True
    else:
        dict_hash_status['hash_status'][nthash[:5]].update({nthash[5:]:0})

    return leaked

def make_full_rescan_after_api_date_modification():

    full_rescan = False
    if requests.get("https://haveibeenpwned.com/api/v3/latestbreach").json()["ModifiedDate"].split("T")[0] != dict_hash_status.get('last_scan_api_modification_date',''):
        dict_hash_status['last_scan_api_modification_date'] = requests.get("https://haveibeenpwned.com/api/v3/latestbreach").json()["ModifiedDate"].split("T")[0]
        full_rescan = True

    
    return full_rescan

def export_results_to_cache_file():

    with open(config.get('common','local_json'), "w+",encoding = 'utf-8') as outfile:
        outfile.write(json.dumps(dict_hash_status))

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
            if nthash[:5] in dict_hash_status['hash_status']:
                if nthash[5:] in dict_hash_status['hash_status'][nthash[:5]]:
                    if dict_hash_status['hash_status'][nthash[:5]][nthash[5:]] > 0 :
                        leaked = True
            else:
                if check_nthash_online_if_needed(nthash):
                    leaked = True
        else:
            if check_nthash_online_if_needed(nthash):
                leaked = True
        if leaked:
            found+=1
            for user in dict_hash[nthash]['accounts']:
                users_leak_dict[user]=str(dict_hash_status['hash_status'][nthash[:5]][nthash[5:]])
                current_users_with_leaked_password.append(user)
                if not user in samba_ad_users_with_leaked_password_group:
                    user_to_add_in_leaked_password_group.append(user)
            if anonymize_results:
                if config.getboolean('common','check_privilegied_group'):
                    datas.append([len(dict_hash[nthash]['anon_accounts']),str(dict_hash_status['hash_status'][nthash[:5]][nthash[5:]]),len(dict_hash[nthash]['privilegied_accounts']),', '.join(dict_hash[nthash]['anon_accounts'][:2]),f'and {len(dict_hash[nthash]["anon_accounts"][2:])} more'])
                else:
                    datas.append([len(dict_hash[nthash]['anon_accounts']),str(dict_hash_status['hash_status'][nthash[:5]][nthash[5:]]),', '.join(dict_hash[nthash]['anon_accounts'][:2]),f'and {len(dict_hash[nthash]["anon_accounts"][2:])} more'])
            else:
                if config.getboolean('common','check_privilegied_group'):
                    datas.append([len(dict_hash[nthash]['anon_accounts']),str(dict_hash_status['hash_status'][nthash[:5]][nthash[5:]]),len(dict_hash[nthash]['privilegied_accounts']),', '.join(dict_hash[nthash]['accounts'][:2]),f'and {len(dict_hash[nthash]["accounts"][2:])} more'])
                else:
                    datas.append([len(dict_hash[nthash]['accounts']),str(dict_hash_status['hash_status'][nthash]),', '.join(dict_hash[nthash]['accounts'][:2]),f'and {len(dict_hash[nthash]["anon_accounts"][2:])} more'])

    print("\n")
    if config.getboolean('common','check_privilegied_group'):
        print(tabulate(datas, headers=["Number of accounts","Number of leaks","Privilegied accounts","Accounts","How much More ?"]))
    else:
        print(tabulate(datas, headers=["Number of accounts","Number of leaks", "Accounts","How much More ?"]))

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

def get_date_from_timestamp(timestamp=None,delta=False):
    timestamp = float(int(str(timestamp)))
    seconds_since_epoch = timestamp/10**7
    loc_dt = datetime.fromtimestamp(seconds_since_epoch)
    loc_dt -= timedelta(days=(1970 - 1601) * 365 + 89)
    if delta:
        data = (loc_dt-delta).days
    else:
        data = loc_dt.strftime('%d/%m/%Y')

    return data

def export_results_to_xslx(output_file=None):

    breached_passwords = []
    identical_passwords = []
    now = datetime.now()
    for u in current_users_with_leaked_password:
        for user in samdb.search(samdb.get_default_basedn(), expression=(f"(sAMAccountName={u})"), scope=ldb.SCOPE_SUBTREE):

            last_logon = get_date_from_timestamp(timestamp=user.get("lastlogon",[b''])[0].decode('utf-8'),delta=now) if user.get("lastLogon",[b''])[0].decode('utf-8') != "" else -100000
            last_logon_timestamp = get_date_from_timestamp(timestamp=user.get("lastlogonTimestamp",[b''])[0].decode('utf-8'),delta=now) if user.get("lastlogonTimestamp",[b''])[0].decode('utf-8') != "" else -100000
            last_logged_in = abs(min(last_logon,last_logon_timestamp))

            datas = {
                "Privilegied"                   : True if u in privilegied_accounts else False,
                "Number of leaks"               : users_leak_dict.get(u),
                "Account"                       : user.get("displayName",[b''])[0].decode('utf-8') if not anonymize_results else "@n0nym0u$",
                "sAMAccountName"                : u if not anonymize_results else users_dict[u],
                "Mail"                          : user.get("mail",[b''])[0].decode('utf-8') if not anonymize_results else "@n0nym0u$",
                "Last Logon (days ago)"         : last_logged_in,
                "Password age (days)"           : abs(get_date_from_timestamp(timestamp=user.get("pwdLastSet",[b''])[0].decode('utf-8'),delta=now)),
                "Location"                      : user.get("distinguishedName",[b''])[0].decode('utf-8') if not anonymize_results else "@n0nym0u$",
            }
            breached_passwords.append(datas)
    
    for h in dict_hash:
        if len(dict_hash[h]['accounts']) > 1:
            datas = {
                "Number of accounts"            : len(dict_hash[h]['accounts']),
                "Number of privilegied accounts": len(dict_hash[h]['privilegied_accounts']),
                "Accounts"                      : dict_hash[h]['accounts'] if not anonymize_results else dict_hash[h]['anon_accounts']
            }
            identical_passwords.append(datas)
    
    df_breached_passwords = pd.DataFrame(breached_passwords)
    df_identical_passwords = pd.DataFrame(identical_passwords)

    writer = pd.ExcelWriter(output_file, engine='xlsxwriter')
    df_breached_passwords.to_excel(writer, sheet_name="Breached Passwords", index=False)
    df_identical_passwords.to_excel(writer, sheet_name="Identical Passwords", index=False)

    workbook = writer.book
    worksheet = writer.sheets["Breached Passwords"]

    (max_row, max_col) = df_breached_passwords.shape
    column_settings = [{"header": column} for column in df_breached_passwords.columns]
    worksheet.add_table(0, 0, max_row, max_col - 1, {"columns": column_settings})
    worksheet.set_column(0, max_col - 1, 12)

    worksheet = writer.sheets["Identical Passwords"]
    (max_row, max_col) = df_identical_passwords.shape
    column_settings = [{"header": column} for column in df_identical_passwords.columns]
    worksheet.add_table(0, 0, max_row, max_col - 1, {"columns": column_settings})
    worksheet.set_column(0, max_col - 1, 12)
    writer.close()

def audit_passwords():

    create_dict_hash()

    if check_duplicate_passwords:
        run_check_duplicate_passwords(dict_hash=dict_hash)

    if check_leaked_passwords:
        run_check_leaked_passwords(dict_hash=dict_hash)

        if config.getboolean('common', 'add_users_in_leaked_passwords_group'):
            create_ad_group_if_needed(group_name=leaked_password_group)
            add_remove_users_ad_group()

    export_results_to_cache_file()

    if config.has_option('common','export_results_to_xlsx'):
        export_results_to_xslx(output_file=config.get('common','export_results_to_xlsx'))
    
    print('\n')

if __name__ == '__main__':
    audit_passwords()
