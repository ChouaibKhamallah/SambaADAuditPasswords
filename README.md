# SAMBA ACTIVE DIRECTORY AUDIT PASSWORDS

This script audit Samba Active Directory duplication and leaked users passwords from haveibeenpwned online database.

# FEATURES

This script, which can simply be administered from a conf.ini file, audits your Samba Active Directory users passwords, checking whether the same password is used by several users, and whether any users have a password present in the famous haveibeenpwned database. 

If you wish, the script can manage a group in your Samba Active Directory to retrieve users with a password present in the haveibeenpwned database. This group can then be managed to notify the users in it, to encourage them to change their password, or to remind them of the basic rules for choosing their password... This is just one example. 

This script can also anonymize the results. 

This is just the beginning of the adventure, with more features to come, such as mail reporting, auditing of passwords that have remained unchanged for x amount of time..

## Results without anonymization

![alt text](https://github.com/ChouaibKhamallah/SambaADAuditPasswords/blob/main/example.png?raw=true)

## Results with anonymization

![alt text](https://github.com/ChouaibKhamallah/SambaADAuditPasswords/blob/main/example_anonymization.png?raw=true)

# INSTALL NOTES

- Connect to Samba Active Directory server

- Launch commands

```
apt-get install git python3-pip
cd /tmp
git clone https://github.com/ChouaibKhamallah/SambaADAuditPasswords.git
mv SambaADAuditPasswords /opt/SambaADAuditPasswords
pip3 install -r /opt/SambaADAuditPasswords/requirements.txt
```

- Configure ini file if needed
  - By default the script run in dry_run mode and audit all domain directories

```
/opt/SambaADAuditPasswords/conf.ini
```

# LAUNCH AUDIT

```
python3 /opt/SambaADAuditPasswords/audit_password.py
```
