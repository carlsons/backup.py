#! /usr/bin/python

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# import needed modules

import sys
import os
import stat

import collections

import traceback
import pprint

import argparse

import time

import pwd
import grp

TIME_FMT='%Y-%m-%d %H:%M:%S'

DEBUG = False
VERBOSE = True

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# helper functions, for classifying directory entries

IS_BLK      = "BLK"
IS_CHAR     = "CHAR"
IS_DIR      = "DIR"
IS_FIFO     = "FIFO"
IS_FILE     = "FILE"
IS_LINK     = "LINK"
IS_SOCK     = "SOCK"
IS_UNKNOWN  = "UNKNOWN"

DIR_ENTRY_TYPES = [
   IS_BLK,
   IS_CHAR,
   IS_DIR,
   IS_FIFO,
   IS_FILE,
   IS_LINK,
   IS_SOCK,
   IS_UNKNOWN,
]

# these strings enumerate the different difference categories
CAT_SAME    = "SAME"
CAT_DIFF    = "DIFF"
CAT_SRC     = "SRC"
CAT_DST     = "DST"
CAT_TYPE    = "TYPE"

CAT_ALL     = [
   CAT_SAME,
   CAT_DIFF,
   CAT_SRC,
   CAT_DST,
   CAT_TYPE,
]

def get_stat( file_spec ):
      return os.lstat( file_spec )

def get_stat_type( file_spec ):

   try:
      stat_obj = get_stat( file_spec )
   except OSError as err:
      print "ERROR: %s" % err
      sys.exit(1)

   if stat.S_ISBLK( stat_obj.st_mode ):
      return IS_BLK

   if stat.S_ISCHR( stat_obj.st_mode ):
      return IS_CHAR

   if stat.S_ISFIFO( stat_obj.st_mode ):
      return IS_FIFO

   if stat.S_ISSOCK( stat_obj.st_mode ):
      return IS_SOCK

   if stat.S_ISDIR( stat_obj.st_mode ):
      return IS_DIR

   if stat.S_ISLNK( stat_obj.st_mode ):
      return IS_LINK

   if stat.S_ISREG( stat_obj.st_mode ):
      return IS_FILE

   raise AssertionError

   # not nececssary, as we're raising an exception here
   # return IS_UNKNOWN

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# DEBUG functions

def DEBUG_emit_compare_object( tag, obj ):
      print "%s: %s: root=%s rel_path=%s name=%s" %( tag, obj.ftype, obj.root, obj.rel_path, obj.name )

def DEBUG_emit_compare_banner( src, dst ):

   if DEBUG:
      print """
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
DEBUG: COMPARING OBJECTS
"""
      DEBUG_emit_compare_object( "src", src )
      DEBUG_emit_compare_object( "dst", dst )
      print ""

def DEBUG_dump_set( name, obj ):

   if DEBUG:
      print "%12s: %s" % ( name, pprint.pformat( obj ) )


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# helper classes and functions

class RootObj:

   def __init__( self ):
      pass

   def __str__( self ):
      return pprint.pformat( self.__dict__ )

   def __repr__( self ):
      return self.__str__()

   def dump( self ):
      #pprint.pprint( self.__dict__ )
      print "\nDUMP: class '%s'\n%s" % ( self.__class__, self )


class PermsObj( RootObj ):

   perms = [
      '---',
      '--x',
      '-w-',
      '-wx',
      'r--',
      'r-x',
      'rw-',
      'rwx'
   ]

   sperms = [
      '---',
      '--s',
      '-w-',
      '-ws',
      'r--',
      'r-s',
      'rw-',
      'rws'
   ]

   def __init__( self, stat_info ):
      RootObj.__init__( self )
      self.val   = stat.S_IMODE( stat_info.st_mode )

   def __str__( self ):
      return "%s" % oct( self.val )

   def __eq__( self, other ):
      return self.val == other.val

   def get_rwx( self ):

      v = self.val

      o = v % 8
      v /= 8

      g = v % 8
      v /= 8

      u = v % 8
      v /= 8

      s = v % 8

      rc = ""

      if s & 4:
         rc += PermsObj.sperms[u]
      else:
         rc += PermsObj.perms[u]

      if s & 2:
         rc += PermsObj.sperms[g]
      else:
         rc += PermsObj.perms[g]

      rc += PermsObj.perms[o]

      return rc


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# this class identifies two corresponding BaseObj objects

class DiffObj( RootObj ):

   def __init__( self, src, dst ):

      if src:
         assert issubclass( src.__class__, BaseObj )

      if dst:
         assert issubclass( dst.__class__, BaseObj )

      # call the base class constructor
      RootObj.__init__( self )

      self.src = src
      self.dst = dst

      self.fields = []

      self.ftype_mismatch = False

      self.show_methods  = {
         CAT_SAME    : self.__show_same,
         CAT_DIFF    : self.__show_diff,
         CAT_SRC     : self.__show_src_only,
         CAT_DST     : self.__show_dst_only,
         CAT_TYPE    : self.__show_diff_type,
      }

   def add_field( self, field ):
      self.fields.append( field )
      if field == "ftype":
         self.ftype_mismatch = True

   def has_diffs( self ):
      return len( self.fields )

   def get_objs( self ):
      return [ self.src, self.dst ]

   def get_category( self ):

      if self.src and not self.dst:
         return CAT_SRC # "SRC"

      if not self.src and self.dst:
         return CAT_DST # "DST"

      if not self.fields:
         return CAT_SAME # "SAME"

      if self.ftype_mismatch:
         return CAT_TYPE # "TYPE"

      return CAT_DIFF # "DIFF"

   def get_key( self ):

      if self.src and self.dst:

         assert self.src.rel_path == self.dst.rel_path
         assert self.src.name     == self.dst.name

         return self.src.get_relspec()

      if self.src:
         return self.src.get_relspec()

      return self.dst.get_relspec()

   def get_fields( self ):
      return ",".join( self.fields )

   def scan( self ):
      if self.src and self.src.isdir():
         self.src.scan()
      if self.dst and self.dst.isdir():
         self.dst.scan()

   def show( self ):

      fn = self.show_methods[ self.get_category() ]
      fn()

   @staticmethod
   def __show( obj ):
      print "%8s: %-40s (%s)" % ( obj.get_category(), obj.get_key(), obj.get_fields() )

   def __show_same( self ):
      self.__show( self )

   def __show_diff( self ):
      self.__show( self )

   def __show_src_only( self ):
      self.__show( self )

   def __show_dst_only( self ):
      self.__show( self )

   def __show_diff_type( self ):
      self.__show( self )


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# this class collects a set of DiffObj objects in category specific
# dictionaries

class DiffSet( RootObj ):

   def __init__( self ):

      # call the base class constructor
      RootObj.__init__( self )

      # collections
      self.all       = dict()
      self.same      = dict()
      self.diff      = dict()
      self.src_only  = dict()
      self.dst_only  = dict()
      self.diff_type = dict() 

      self.category  = {
         CAT_SAME    : self.same,
         CAT_DIFF    : self.diff,
         CAT_SRC     : self.src_only,
         CAT_DST     : self.dst_only,
         CAT_TYPE    : self.diff_type,
      }


   def add_entry( self, diff_obj ):

      assert isinstance( diff_obj, DiffObj )

      # get the key and category for this difference entry
      diff_key = diff_obj.get_key()
      diff_cat = diff_obj.get_category()
      # get the dictionary for the given category
      cat_dict = self.category[ diff_cat ]

      # make sure we don't have any duplicates
      assert not cat_dict.has_key( diff_key )

      # insert the object into the appropriate dictionary
      cat_dict[ diff_key ] = diff_obj
      # add it to the superset
      self.all[ diff_key ] = diff_obj

   # not currently used
   def __show( self ):

      for cat_name in CAT_ALL:
         cat = self.category[ cat_name ]
         for key in cat.keys():
            print "%8s: %s" % ( cat_name, key )

   def show( self ):

      keys = self.all.keys()
      keys.sort()

      for key in keys:
         diff_obj = self.all[ key ]
         diff_obj.show()



   def dump( self ):

      print """
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
DEBUG: DUMPING DIFFERENCES
"""
      print "DUMP: class '%s'" % self.__class__

      for cat_name in CAT_ALL:

         print """
--------------------------------------------------------------------------------
DEBUG: DUMPING CATEGORY
"""
         print "DUMP: category '%s'" % cat_name

         cat = self.category[ cat_name ]

         for key in cat.keys():

            print "\nDUMP: entry '%s'" % key

            cat[ key ].dump()


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# this is the main "application" class

class DiffScanner( RootObj ):

   def __init__( self, src_input, dst_input, preserve = False ):

      assert isinstance( src_input, basestring )
      assert isinstance( dst_input, basestring )

      self.src_input = src_input
      self.src       = None         # placeholder
      self.dst_input = dst_input
      self.dst       = None         # placeholder

      self.preserve  = preserve     # whether we preserve "same" entries

      self.started   = False

      self.diff_set  = None

      self.dir_queue = list()


   def run( self ):

      # disallow reuse of an object
      assert not self.started

      self.src = mk_entry( self.src_input )
      self.dst = mk_entry( self.dst_input )

      diff_obj = self.__compare( self.src, self.dst )

      # TODO: this needs to be refactored so that the scan is not recursive

      if self.dst.isdir() and self.src.isdir():

         self.diff_set = DiffSet()
         self.__compare_children( self.src, self.dst )

      while len( self.dir_queue ):

         diff_obj = self.dir_queue.pop(0)
         self.__compare_children( *diff_obj.get_objs() )

      # TODO: this needs to be moved to the cmdline processing context
      self.diff_set.show()


   def __compare( self, src, dst ):

      DEBUG_emit_compare_banner( src, dst )

      if dst.get_spec() == src.get_spec():
         print "ERROR: comparing an object to itself"
         sys.exit()

      if src.ftype != dst.ftype:

         diff_obj = DiffObj( src, dst )
         diff_obj.add_field( "ftype" )

         # print "\nDEBUG: diff_object category: %s" % diff_obj.get_category()

         return diff_obj   # <<<--- EARLY EXIT

      # at this point we know the ftypes are the same, so we can use either one
      ftype = dst.ftype
      # get the class object associated with this file type
      dentry_class = get_class( ftype )
      # get the static comparison function
      compare_fn = dentry_class.compare

      # do the comparison and get the diff object
      diff_obj = compare_fn( src, dst )

      # print "\nDEBUG: diff_object category: %s" % diff_obj.get_category()

      return diff_obj


   def __compare_children( self, src_obj, dst_obj ):

      assert src_obj.isdir()
      assert dst_obj.isdir()

      src_obj.scan()
      dst_obj.scan()

      # get the keys (i.e.: the names) of the entries from both dst and src
      src_key_set    = set( src_obj.get_child_keys() )
      dst_key_set    = set( dst_obj.get_child_keys() )
      # find the intersection, i.e.: the entry names that appear in both the dst and src
      intersect_keys = dst_key_set.intersection( src_key_set )
      # now subtract out the intersection to get what's unique in both
      src_only_keys  = src_key_set - intersect_keys
      dst_only_keys  = dst_key_set - intersect_keys

      # dump the sets for debugging purposes
      # these are the base sets
      DEBUG_dump_set( "src_set",    src_key_set )
      DEBUG_dump_set( "dst_set",    dst_key_set )
      # these are the actual categories
      DEBUG_dump_set( "src_only",   src_only_keys )
      DEBUG_dump_set( "intersect",  intersect_keys )
      DEBUG_dump_set( "dst_only",   dst_only_keys )

      # create DiffObj instances for orphans and add them to the diff_set
      self.__copy_children( src_obj, src_only_keys, lambda obj: DiffObj( obj,  None ) )
      self.__copy_children( dst_obj, dst_only_keys, lambda obj: DiffObj( None, obj ) )

      for name in intersect_keys:

         src = src_obj.entries[ name ]
         dst = dst_obj.entries[ name ]

         diff_obj = self.__compare( src, dst )

         self.diff_set.add_entry( diff_obj );

         if src.isdir() and dst.isdir():
            self.dir_queue.append( diff_obj )

      if src.isdir():
         src.reset()

      if dst.isdir():
         dst.reset()


   def __copy_children( self, from_dir, names, mk_diff_fn ):

      for name in names:
         # get the source object
         obj = from_dir.entries[ name ]
         # create a diff entry for it
         diff_obj = mk_diff_fn( obj );
         # and adde it to the result
         self.diff_set.add_entry( diff_obj )


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

class ListScanner( RootObj ):

   def __init__( self, inputs ):

      self.inputs   = inputs

      self.objs      = dict()
      self.dir_queue = list()


   def run( self ):

      # step 1 - iterate the inputs and create objects for each

      for file_spec in self.inputs:

         # split this input to get the root and name values
         root = os.path.dirname( file_spec )
         name = os.path.basename( file_spec )

         # make an entry for it
         obj = mk_entry( root, None, name )
         # and add it to the dictionary
         self.objs[ obj.get_relspec() ] = obj

         if obj.isdir():
            self.dir_queue.append( obj )

      # step 2 - scan the directory queue to scan the tree

      while len( self.dir_queue ):

         obj = self.dir_queue.pop(0)
         obj.scan()

         if obj.entries:

            entry_names = obj.get_child_keys()
            for entry_name in entry_names:

               child = obj.entries[ entry_name ]

               self.objs[ child.get_relspec() ] = child

               if child.isdir():
                  self.dir_queue.append( child )

            obj.reset()

      # step 3 - show the list

      names = self.objs.keys()
      names.sort()

      for name in names:
         self.objs[ name ].show()


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# this is the base class for all directory entry objects, i.e.: files, links
# and directories

class BaseObj( RootObj ):

   # these are helper functions used by the derived class to compare the objects

   @staticmethod
   def compare_field( src, dst, field ):

      dst_val = dst.__dict__[ field ]
      src_val = src.__dict__[ field ]

      is_equal = False
      if dst_val == src_val:
         is_equal = True

      # print "DEBUG: %s.%s: '%s' %s= '%s'" % ( dst.__class__, field, dst_val, ( "=" if is_equal else "!" ), src_val )

      return is_equal

   @staticmethod
   def compare_fields( src, dst, fields, check_name = False ):

      assert src.__class__ == dst.__class__
      assert issubclass( src.__class__, BaseObj )

      if check_name:
         assert dst.name == src.name

      diff_obj = DiffObj( src, dst )

      for field in fields:

         if not BaseObj.compare_field( src, dst, field ):
            diff_obj.add_field( field )

      return diff_obj

   def __init__( self, root, rel_path, name, ftype ):

      RootObj.__init__( self )

      self.root         = root
      self.rel_path     = rel_path
      self.name         = name
      self.name_desc    = name
      self.ftype        = ftype
      self.ftype_desc   = '-'

      self.stat_info    = get_stat( self.get_spec() )

      self.perm         = PermsObj( self.stat_info )
      self.uid          = self.stat_info.st_uid
      self.gid          = self.stat_info.st_gid
      self.size         = self.stat_info.st_size

      self.ctime        = self.stat_info.st_ctime  # meta-data changed (created?)
      self.mtime        = self.stat_info.st_mtime  # modified
      self.atime        = self.stat_info.st_atime  # accessed

   def isdir( self ):
      return False

   def get_spec( self ):
      assert self.root
      return join_path( self.root, self.rel_path, self.name )

   def get_relspec( self ):
      assert self.name
      return join_path( self.rel_path, self.name )

   def show( self ):

      print "%4s: %5s/%c%s %4d/%-8s %4d/%-8s %8d %s %-30s %s" % (
         self.ftype,
         self.perm,
         self.ftype_desc,
         self.perm.get_rwx(),
         self.uid,
         pwd.getpwuid( self.uid ).pw_name,
         self.gid,
         grp.getgrgid( self.gid ).gr_name,
         self.size,
         time.strftime( TIME_FMT, time.localtime( self.mtime )),
         self.rel_path if self.rel_path else ".",
         self.name_desc
         )



# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# file object

class FileObj( BaseObj ):

   # TODO: setup comparison fields and related

   compare_fields = (
      "name",           # TODO: this should be controlled by the check_name parameter
      "ftype",
      "perm",
      "uid",
      "gid",
      "size",
      "mtime",
   )

   @staticmethod
   def compare( src, dst, check_name = False ):

      diff_obj = BaseObj.compare_fields( src, dst, FileObj.compare_fields, check_name )
      return diff_obj

   def __init__( self, root, rel_path, name ):
      BaseObj.__init__( self, root, rel_path, name, IS_FILE )

      # TODO: get the file size and other relevant details and add them
      # as fields for the compare_field function


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# link object

class LinkObj( BaseObj ):

   # TODO: setup comparison fields and related

   compare_fields = (
      "name",           # TODO: this should be controlled by the check_name parameter
      "ftype",
      "uid",
      "gid",
      "size",
      "mtime",
      "link",
   )

   @staticmethod
   def compare( src, dst, check_name = False ):

      diff_obj = BaseObj.compare_fields( src, dst, LinkObj.compare_fields, check_name )
      return diff_obj

   def __init__( self, root, rel_path, name ):
      BaseObj.__init__( self, root, rel_path, name, IS_LINK )

      # TODO: read the link and add a "points_to" member...

      self.link = os.readlink( self.get_spec() )

      self.name_desc    = self.name + ' -> ' + self.link
      self.ftype_desc   = 'l'


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# directory object

class DirObj( BaseObj ):

   compare_fields = (
      "name",           # TODO: this should be controlled by the check_name parameter
      "ftype",
      "perm",
   )

   @staticmethod
   def compare( src, dst, check_name = False ):

      diff_obj = BaseObj.compare_fields( src, dst, DirObj.compare_fields, check_name )
      return diff_obj

   def __init__( self, root, rel_path = None, name = None ):

      root              = os.path.abspath( root )

      BaseObj.__init__( self, root, rel_path, name, IS_DIR )

      self.entries      = None
      self.scanned      = False

      self.ftype_desc   = 'l'

      # print "DEBUG: dir: %s" % self.__class__

   def __mk_entry( self, entry_name ):
      # get the relative path of the entry
      rel_path = join_path( self.rel_path, self.name )
      # and make an entry for it
      return mk_entry( self.root, rel_path, entry_name )

   def isdir( self ):
      return True

   def scan( self ):

      if not self.scanned:
         self.scanned      = True

         entry_names       = os.listdir( self.get_spec() )

         if entry_names:

            self.entries = dict()

            entry_names.sort();
            for entry_name in entry_names:
               self.entries[ entry_name ] = self.__mk_entry( entry_name )

   def get_child_keys( self ):

      if self.entries:
         keys = self.entries.keys()
         keys.sort()
         return keys

      return list()

   def reset( self ):

      if self.scanned:
         self.entries = dict()
         self.scanned = False

   def dump( self ):

      if self.entries:

         print self

         print "\nDUMP: directory entries for: %s" % self.get_spec()

         for k in self.get_child_keys():

            print "\nDUMP: entry for %s" % k
            print "DUMP: dir(%s) == %s" % ( k, dir( self.entries[k] ) )
            self.entries[k].dump()

      else:

         print self

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# factory method for generating the appropriate object for a given directory
# entry

DIR_ENTRY_CLASSES = {
   IS_DIR   : DirObj,
   IS_FILE  : FileObj,
   IS_LINK  : LinkObj

   # TODO: what about all of the other file types

}

def get_class( ftype ):

   if DIR_ENTRY_CLASSES.has_key( ftype ):
      return DIR_ENTRY_CLASSES[ ftype ]

   raise AssertionError


def join_path( *args ):

   file_spec = None

   for arg in args:
      if arg:
         if not file_spec:
            file_spec = arg
         else:
            file_spec = os.path.join( file_spec, arg )

   return file_spec

def mk_entry( root, rel_path = None, name = None ):

   # canonicalize the root path
   abs_root    = os.path.abspath( root )
   # construct the file specification
   file_spec   = join_path( abs_root, rel_path, name )
   # get the file type
   ftype       = get_stat_type( file_spec )

   # print "DEBUG: making entry for '%s' of type '%s'" % ( file_spec, ftype )

   if DIR_ENTRY_CLASSES.has_key( ftype ):
      dentry_class   = DIR_ENTRY_CLASSES[ ftype ]
      return dentry_class( abs_root, rel_path, name )

   raise AssertionError



# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-



# top-level run commands, for processing command line modes

def run_test( args = None ):

   if not args:
      args = sys.argv[1:]
   if len( args ) != 3:
      print "ERROR: specify <src dir> <dst dir> <name>"
      sys.exit(1)

   dir_src, dir_dst, name = args

   src = mk_entry( '.', dir_src, name )
   dst = mk_entry( '.', dir_src, name )

   de = DiffObj( src, dst )
   de.add_field( "ftype" )

   ds = DiffSet()
   ds.add_entry( de )

   ds.dump()


def run_list( args = None ):

   if not args:
      args = sys.argv[1:]
   if not len( args ):
      print "ERROR: specify one or more things to dump..."
      sys.exit(1)

   ls = ListScanner( args )
   ls.run()


def run_diff( args = None ):

   if not args:
      args = sys.argv[1:]
   if len( args ) != 2:
      print "ERROR: specify exactly 2 objects to compare"
      sys.exit()

   # get the args
   src, dst = args
   # and call the comparison function
   ds = DiffScanner( src, dst )
   ds.run()

COMMANDS = {
   "TEST"   : run_test,
   "LIST"   : run_list,
   "DIFF"   : run_diff,
}



# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

#  __  __    _    ___ _   _
# |  \/  |  / \  |_ _| \ | |
# | |\/| | / _ \  | ||  \| |
# | |  | |/ ___ \ | || |\  |
# |_|  |_/_/   \_\___|_| \_|
# TAGS: MAIN

if __name__ == "__main__":

   parser = argparse.ArgumentParser( "directory scanning, comparison and backup" )

   mode = parser.add_mutually_exclusive_group( required=True )
   mode.add_argument( "-d", "--diff", action="store_const", const="DIFF", dest="mode", help="enables differencing mode"  )
   mode.add_argument( "-l", "--list", action="store_const", const="LIST", dest="mode", help="enables list mode" )
   mode.add_argument( "-t", "--test", action="store_const", const="TEST", dest="mode", help="enables bench testing" )

   parser.add_argument( "--debug",    action="store_true",  default=False,             help="dump debugging information" )
   parser.add_argument( "--verbose",  action="store_true",  default=False,             help="include extra information, where applicable" )

   parser.add_argument( "scopes", nargs=argparse.REMAINDER )

   args = parser.parse_args()

   DEBUG    = args.debug
   VERBOSE  = args.verbose

   if VERBOSE:
      print "mode=%s"      % args.mode
      print "debug=%s"     % args.debug
      print "verbose=%s"   % args.verbose
      print "scopes=%s"    % args.scopes

   fn = COMMANDS[ args.mode ]
   fn( args.scopes )


# vim: syntax=python si
