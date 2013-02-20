#!/opt/opsware/bin/python2

import sys
sys.path.append("/opt/opsware/pylibs2")

import pdb
from pytwist import *
from getpass import getpass
from optparse import OptionParser
from pytwist.com.opsware.fido import FolderACL
from pytwist.com.opsware.search import Filter
from pytwist.com.opsware.common import NotFoundException
from pytwist.com.opsware.fido import AuthenticationException

class NoSuchFolder(Exception):
    pass
    
class NoSuchRole(Exception):
    pass

class RequiredArgMissing(Exception):
    pass

class FolderTransaction(object):
    def __init__(self, ts, folder):
        self.ts = ts
        self.fs = self.ts.folder.FolderService
        self.facls = []
        self.roles = []
        self.folder = self.get_folder(folder)

    def set_acl(self, acls):
        if hasattr(acls, 'pop'):
            self.facls = acls
        else:
            self.facls.append(acls)

    def get_folder(self, folder):
        debug("Looking for %s" % folder)
        flist = folder.split('/')[1:]
        try:
            fref = self.fs.getFolderRef(flist)
        except NotFoundException:
            raise NoSuchFolder, folder
        return fref

    def set_role(self, role):
        filter = Filter()
        filter.expression = 'UserRoleVO.rolename =* %s' % role
        self.roles = self.ts.fido.UserRoleService.findUserRoleRefs(filter)
        if len(self.roles) == 0:
            raise NoSuchRole, role

    def get_facls(self):
        facls = self.fs.getFolderACLs([self.folder])
        return facls

    def remove_facls(self, cur_facls, role, recurse):
        debug("Removing existing FACLs for %s:" % role.name)
        for facl in cur_facls:
            if facl.role.id == role.id:
                debug("Removing FACL R(%s) A(%s) F(%s)" % (facl.role.name,
                    facl.accessLevel, facl.folder.name))
                self.fs.removeFolderACLs([facl], recurse)
        
    def update(self, recurse=False):
        current_facls = self.get_facls()
        for role in self.roles:
            facl_list = []
            debug("Creating FACLS for %s" % role.name)
            for acl in self.facls:
                if acl == 0:
                    break
                facl = FolderACL()
                facl.accessLevel = acl
                facl.role = role
                facl.folder = self.folder
                facl_list.append(facl)
                debug("Created FACL: R(%s) A(%s) F(%s)" % (facl.role.name, acl,
                facl.folder.name))
            try:
                self.remove_facls(current_facls, role, recurse)
                debug("Adding new FACLs for %s" % role.name)
                for facl in facl_list:
                    debug("Adding FACL: R(%s) A(%s) F(%s)" % (facl.role.name, 
                        facl.accessLevel, facl.folder.name))
                self.fs.addFolderACLs(facl_list, recurse, True)
            except:
                # Something bad happened here! Add back all 
                # the facl's we may have removed
                self.fs.addFolderACLs(current_facls, recurse, True)

def get_expanded_perms(perms):
    facls = []
    if perms.count('e'):
        facls.append('PM')
    if perms.count('x'):
        facls.append('X')
    if perms.count('w'):
        facls.append('WRITE')
    elif perms.count('r'):
        facls.append('READ')
    elif perms.count('l'):
        facls.append('L')
    if perms.count == '0':
        facls = [0]
    return facls

def print_acls(folder, acls):
    print "Folder: %s" % folder
    print "%30s %30s" % ("Role".center(30),"Permission".center(30))
    print "=" * 60 
    for acl in acls:
        print "%30s %30s" % (acl.role.name.ljust(30), acl.accessLevel.ljust(30))
        
def print_permhelp():
    perm_help = """
HP SA Permission Help
=====================

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

Examples:

1) Apply all permissions:

    --perms wxe

    This applies LIST, READ, WRITE, EXECUTE and EDIT.

2) Apply LIST and READ:
    
    --perms r

    This applies LIST and READ.

3) Apply READ and EXECUTE:

    --perms rx

    This applies LIST, READ and EXECUTE.

4) Apply WRITE AND EXECUTE:

    --perms wx

    This applies LIST, READ, WRITE and EXECUTE.

5) Delete all permissions:

    --perms 0

    This will delete all permissions for the roles specified
"""

    print perm_help

def debug(msg):
    if debug.on:
        print msg

def get_parser():
    parser = OptionParser()
    parser.add_option('-p','--perm',
        help="Permissions to add. See the README or --permhelp for more details")
    parser.add_option('-l','--list',action="store_true",
        help="List the current permissions on the folder")
    parser.add_option('-r','--roles', action='append',
        help="The roles to add. Implements partial matching or multiple roles")
    parser.add_option('-f','--folder',
        help="The folder to add the permissions to")
    parser.add_option('-R','--recurse',action='store_true',
        help="Apply the permissions recursively")
    parser.add_option('-u','--username',
        help="Your SA username")
    parser.add_option('-d','--debug',action='store_true',
        help="Set debugging to true")
    parser.add_option('--permhelp',action='store_true',
        help="Print help on permissions")
    return parser

def get_twist(user):
    ts = twistserver.TwistServer()
    password = getpass("Password: ")
    try:
        ts.authenticate(user, password)
    except AuthenticationException:
         raise AuthenticationException
    return ts

def validate_args(options):
    if options.permhelp:
        return

    if not options.username:
        raise RequiredArgMissing, 'username'

    if not options.folder:
        raise RequiredArgMissing, 'folder'

    if options.list:
        return

    if not options.perm:
        raise RequiredArgMissing, 'perms'

    if not options.roles:
        raise RequiredArgMissing, 'roles'

    if not options.recurse:
        options.recurse = False

def main(args):
    parser = get_parser()
    (options, args) = parser.parse_args()

    try:
        validate_args(options)
    except RequiredArgMissing, e:
        print "You are missing a required argument: '%s'" % e
        return 1 

    if options.permhelp:
        print_permhelp()
        return 0

    if options.debug:
        debug.on = True
    else:
        debug.on = False

    try:
        ts = get_twist(options.username)
    except AuthenticationException:
        print "Invalid login"
        return 1

    try:
        ft = FolderTransaction(ts, options.folder)
    except NoSuchFolder, e:
        print "Folder '%s' does not exist in SA" % e
        return 1

    if options.list:
        acls = ft.get_facls()
        print_acls(options.folder, acls)
    else:
        perms = get_expanded_perms(options.perm)
        ft.set_acl(perms)
        try:
            for role in options.roles:
                ft.set_role(role)
        except NoSuchRole, e:
            print "Role '%s' does not exist in SA" % e
            return 1

        ft.update(options.recurse)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
