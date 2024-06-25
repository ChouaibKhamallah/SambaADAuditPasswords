
# Change Log
All notable changes to this project will be documented in this file.

# 2024-06-25 

## Changed

- Remove GetPasswordCommand (broken in samba 4.20)

# 2023-12-09

## Added

- **Export results to xlsx file** : If you want to export results in xlsx file you can configure the conf.ini set full path on export_results_to_xlsx option

# 2023-11-23

## Changed

- Cache lightening
- Better results organization
- Better output for duplicate privileged accounts

# 2023-11-22

## Added

- **Check for privileged accounts**: If you want to check privileged groups configure the conf.ini file set privilegied_groups names separated by commas, requires check_privilegied_group to be set to True
  
## Changed

- Code simplification

# 2023-11-21

# Added

- **Speed up the process**: json file to store already scanned hashes, the script will scan the hash online not present in the local cache, then add it to the local cache. If the online database is updated, the cache will be completely erased and all hashes will be scanned.
  
# 2023-11-20

## Changed

- Better management of the sambaAD group when a users_basedn filter is configured in the conf.ini file

# 2023-11-19

- Repository creation
