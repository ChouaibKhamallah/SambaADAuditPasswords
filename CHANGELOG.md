
# Change Log
All notable changes to this project will be documented in this file.

# 2023-11-22

# Added

- Check of privileged users: If you want to check privileged groups configure the conf.ini file set privilegied_groups names separated by commas, requires check_privilegied_group to be set to True
  
## Changed

- Code simplification

# 2023-11-21

# Added

- Speed up the process : json file to store already scanned hashes, the script will scan the hash online not present in the local cache, then add it to the local cache. If the online database is updated, the cache will be completely erased and all hashes will be scanned. https://github.com/ChouaibKhamallah/SambaADAuditPasswords/commit/36e25f1fdf61c4fcafa6501abb5162bfb3d9eada
  
# 2023-11-20

## Changed

- Better management of the sambaAD group when a users_basedn filter is configured in the conf.ini file

# 2023-11-19

- Repository creation
