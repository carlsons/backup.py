#! /usr/bin/python

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# import needed modules

import sys
import os
import stat

import collections

import traceback
import pprint

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


class DirEntryPerms( RootObj ):

   def __init__( self, stat_info ):
      RootObj.__init__( self )
      self.val   = stat.S_IMODE( stat_info.st_mode )

   def __str__( self ):
      return "%s" % oct( self.val )

   def __eq__( self, other ):
      return self.val == other.val


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# this is the main "application" class

class DirScanner( RootObj ):

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

         self.dst.scan()
         self.src.scan()

         # TODO: this should return a tuple like:
         # ( same_list, diff_list, src_only_lst, dst_only_list )

         self.__compare_children( self.src, self.dst )

      while len( self.dir_queue ):

         diff_obj = self.dir_queue.pop(0)
         diff_obj.scan()

         self.__compare_children( diff_obj.src, diff_obj.dst )

      # :self.diff_set.dump() # DEBUG

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


   def __compare_children( self, dst_dir, src_dir ):

      assert dst_dir.isdir()
      assert dst_dir.scanned
      assert src_dir.isdir()
      assert src_dir.scanned

      # get the keys (i.e.: the names) of the entries from both dst and src
      src_set     = set( src_dir.entries.keys() )
      dst_set     = set( dst_dir.entries.keys() )
      # find the intersection, i.e.: the entry names that appear in both the dst and src
      intersect   = dst_set.intersection( src_set )
      # now subtract out the intersection to get what's unique in both
      src_only    = src_set - intersect
      dst_only    = dst_set - intersect

      # dump the sets for debugging purposes
      # these are the base sets
      DEBUG_dump_set( "src_set",    src_set )
      DEBUG_dump_set( "dst_set",    dst_set )
      # these are the actual categories
      DEBUG_dump_set( "src_only",   src_only )
      DEBUG_dump_set( "intersect",  intersect )
      DEBUG_dump_set( "dst_only",   dst_only )

      # create DiffObj instances for orphans and add them to the diff_set
      self.__copy_children( src_dir, src_only, DirScanner.__mk_src_only )
      self.__copy_children( dst_dir, dst_only, DirScanner.__mk_dst_only )

      for name in intersect:

         src = src_dir.entries[ name ]
         dst = dst_dir.entries[ name ]

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


   @staticmethod
   def __mk_src_only( obj ):
      return DiffObj( obj, None )

   @staticmethod
   def __mk_dst_only( obj ):
      return DiffObj( None, obj )



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

   def get( self ):
      return ( self.src, self.dst )

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
      self.ftype        = ftype

      self.stat_info    = get_stat( self.get_spec() )

      self.perm         = DirEntryPerms( self.stat_info )
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

   def reset( self ):

      if self.scanned:
         self.entries = dict()
         self.scanned = False

   def dump( self ):

      if self.entries:

         print self

         print "\nDUMP: directory entries for: %s" % self.get_spec()

         keys = self.entries.keys()
         keys.sort()

         for k in keys:

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

#  _____ _____ ____ _____    ____ ___  ____  _____
# |_   _| ____/ ___|_   _|  / ___/ _ \|  _ \| ____|
#   | | |  _| \___ \ | |   | |  | | | | | | |  _|
#   | | | |___ ___) || |   | |__| |_| | |_| | |___
#   |_| |_____|____/ |_|    \____\___/|____/|_____|
# TAGS: TEST CODE

def dump_obj( obj ):

   print """
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
DEBUG: DUMPING OBJECT '%s'
""" % obj.get_spec()

   obj.dump()

   if obj.isdir():

      print "\nDEBUG: scanning...\n"

      obj.scan()

      print "\nDEBUG: dumping again...\n"

      obj.dump()

      print "\nDEBUG: recursing...\n"

      for entry_name in obj.entries.keys():

         print "----------\nDEBUG: CHECKING ENTRY '%s'\n" % entry_name

         child = obj.entries[ entry_name ]

         if child.isdir():
            child.scan()
            child.dump()
            print "" # DEBUG:

def dump_objs( args ):

   for file_spec in args:

      obj = mk_entry( file_spec )
      dump_obj( obj )
      del obj

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# top-level run commands, for processing command line modes

def run_unit_test( args = None ):

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


def run_dump_objs( args = None ):

   if not args:
      args = sys.argv[1:]
   if not len( args ):
      print "ERROR: specify one or more things to dump..."
      sys.exit(1)

   dump_objs( args )


def run_module( args = None ):

   if not args:
      args = sys.argv[1:]
   if len( args ) != 2:
      print "ERROR: specify exactly 2 objects to compare"
      sys.exit()

   # get the args
   src, dst = args
   # and call the comparison function
   ds = DirScanner( src, dst )
   ds.run()






# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

#  __  __    _    ___ _   _
# |  \/  |  / \  |_ _| \ | |
# | |\/| | / _ \  | ||  \| |
# | |  | |/ ___ \ | || |\  |
# |_|  |_/_/   \_\___|_| \_|
# TAGS: MAIN

if __name__ == "__main__":

   if len( sys.argv ) > 1: 

      if sys.argv[1] == '--test':

         run_unit_test( sys.argv[2:] )

      elif sys.argv[1] == '--dump':

         run_dump_objs( sys.argv[2:] )

      elif sys.argv[1] == '--run':

         run_module( sys.argv[2:] )

      else:

         run_module( sys.argv[1:] )

   else:

      print "ERROR: what do you want me to do???"



# vim: syntax=python si
