Opsware Chmod Utility
=====================

This tool provides a method to quickly list and modify the permissions
of a 'Folder' in HP Server Automation.  It operates on one folder at a time,
but allows you to specify multiple roles in one invocation.

This utility is intended to be used on an SA core, although a few
simple modifications can enable it to run on any managed agent.

Command Syntax
---------------------

*Note: For details on the syntax of the --perm option, see the 'Permission
Syntax' section*

```
usage: opswchmod.py [options]

options:
  -h, --help            show this help message and exit
  -p PERM, --perm=PERM  Permissions to add. See the README or --permhelp for
                        more details
  -l, --list            List the current permissions on the folder
  -r ROLES, --roles=ROLES
                        The roles to add. Implements partial matching or
                        multiple roles
  -f FOLDER, --folder=FOLDER
                        The folder to add the permissions to
  -R, --recurse         Apply the permissions recursively
  -u USERNAME, --username=USERNAME
                        Your SA username
  -d, --debug           Set debugging to true
  --permhelp            Print help on permissions
```

### Examples

1. List all permissions for a folder

    `./opswchmod.py --list -f '/Customers/ACME' -u admin`

2. Set permissions on a folder for a user

    `./opswchmod.py --perm wx -r johndoe -f '/Customers/ACME/Scripts' -u admin`

3. Set permissions on a folder, recursively

    `./opswchmod.py --perm wx -r johndoe -f '/Customers/ACME/Scripts' --recurse -u admin`

4. Set permissions on a folder for all groups starting with 'ACME-SYS'

    `./opswchmod.py --perm wxe -r ACME-SYS -f '/Customers/ACME/Policies' -u admin`

5. Remove all permissions on folders for the ACME-SYSOPS group

    `./opswchmod.py --perm 0 -r ACME-SYSOPS -f '/Customers/ACME/Policies' -u admin`


Permission Syntax
---------------------

You can specify a combination of {L,R,W,X,E} or 0

L   = LIST  
R   = READ  
W   = WRITE  
X   = EXECUTE  
E   = EDIT FOLDER PERMISSIONS  
0   = DELETE ALL PERMISSIONS  

Any permission, other than LIST and 0, will also apply LIST.  If you specify
WRITE, this also applies READ, as well as LIST.

0 is exclusive and should not be combined with any other permissions.  It will
override any other permissions specified on the command line.  It's purpose is
to provide a mechanism for removing permissions for a role from a folder.

EXECUTE, EDIT FOLDER and WRITE can all be specified, but never apply 
each other.

### Examples:

1. Apply all permissions:

    `--perms wxe`

    This applies LIST, READ, WRITE, EXECUTE and EDIT.

2. Apply LIST and READ:
    
    `--perms r`

    This applies LIST and READ.

3. Apply READ and EXECUTE:

    `--perms rx`

    This applies LIST, READ and EXECUTE.

4. Apply WRITE AND EXECUTE:

    `--perms wx`

    This applies LIST, READ, WRITE and EXECUTE.

5. Delete all permissions:

    `--perms 0`

    This will delete all permissions for the roles specified
