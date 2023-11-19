SAMBA ACTIVE DIRECTORY PASSWORDS AUDIT
======================================

This script is a fork from sfonteneau audit Samba Active Directory duplication and leaked users passwords from haveibeenpwned online database.


FEATURES
========

This script, which can simply be administered from a conf.ini file, audits your Samba Active Directory users passwords, checking whether the same password is used by several users, and whether any users have a password present in the famous haveibeenpwned database. 

If you wish, the script can manage a group in your Samba Active Directory to retrieve users with a password present in the haveibeenpwned database. This group can then be managed to notify the users in it, to encourage them to change their password, or to remind them of the basic rules for choosing their password... This is just one example. 

This script can also anonymize the results. 

This is just the beginning of the adventure, with more features to come, such as mail reporting, auditing of passwords that have remained unchanged for x amount of time..


FORK IMPROVEMENTS 
=================

- Improved output of results (in tabular form)

- Display of haveibeenpwned online database update date

- Added support for a group in sambaAD to target users with leaked passwords for future automatic notification

- Implementation of a progress bar when checking passwords through the haveibeenpwned API, as this can take a long time for a large number of users.

- Results can be anonymized outputs

Results without anonymization
-----------------------------

![alt text](https://github.com/ChouaibKhamallah/haveibeenpwnd_samba/blob/master/example.png?raw=true)

Results with anonymization
--------------------------

![alt text](https://github.com/ChouaibKhamallah/haveibeenpwnd_samba/blob/master/example_anonymization.png?raw=true)

INSTALL NOTES
=============

- Connect to Samba Active Directory server

- Launch commands

```
apt-get install git python3-pip
cd /tmp
git clone https://github.com/ChouaibKhamallah/haveibeenpwnd_samba.git
mv haveibeenpwnd_samba /opt/haveibeenpwnd_samba
pip3 install -r /opt/haveibeenpwnd_samba/requirements.txt
```

- Configure ini file

```
/opt/haveibeenpwnd_samba/conf.ini
```

LAUNCH AUDIT
============
SAMBA ACTIVE DIRECTORY PASSWORDS AUDIT
======================================

This script is a fork from sfonteneau audit Samba Active Directory duplication and leaked users passwords from haveibeenpwned online database.


FEATURES
========

This script, which can simply be administered from a conf.ini file, audits your Samba Active Directory users passwords, checking whether the same password is used by several users, and whether any users have a password present in the famous haveibeenpwned database. 

If you wish, the script can manage a group in your Samba Active Directory to retrieve users with a password present in the haveibeenpwned database. This group can then be managed to notify the users in it, to encourage them to change their password, or to remind them of the basic rules for choosing their password... This is just one example. 

This script can also anonymize the results. 

This is just the beginning of the adventure, with more features to come, such as mail reporting, auditing of passwords that have remained unchanged for x amount of time..


FORK IMPROVEMENTS 
=================

- Improved output of results (in tabular form)

- Display of haveibeenpwned online database update date

- Added support for a group in sambaAD to target users with leaked passwords for future automatic notification

- Implementation of a progress bar when checking passwords through the haveibeenpwned API, as this can take a long time for a large number of users.

- Results can be anonymized outputs

Results without anonymization
-----------------------------

![alt text](https://github.com/ChouaibKhamallah/haveibeenpwnd_samba/blob/master/example.png?raw=true)

Results with anonymization
--------------------------

![alt text](https://github.com/ChouaibKhamallah/haveibeenpwnd_samba/blob/master/example_anonymization.png?raw=true)

INSTALL NOTES
=============

- Connect to Samba Active Directory server

- Launch commands

```
apt-get install git python3-pip
cd /tmp
git clone https://github.com/ChouaibKhamallah/haveibeenpwnd_samba.git
mv haveibeenpwnd_samba /opt/haveibeenpwnd_samba
pip3 install -r /opt/haveibeenpwnd_samba/requirements.txt
```

- Configure ini file

```
/opt/haveibeenpwnd_samba/conf.ini
```

LAUNCH AUDIT
============

```
python3 /opt/haveibeenpwnd_samba/audit_password.py
```

```
python3 /opt/haveibeenpwnd_samba/audit_password.py
```
