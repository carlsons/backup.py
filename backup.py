#! /usr/bin/python

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# import needed modules

import sys
import os
import stat
import hashlib

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


class EpochObj( RootObj ):

   def __init__( self, seconds ):

      self.seconds = seconds

   def __str__( self ):
      return time.strftime( TIME_FMT, time.localtime( self.seconds ))

   def __int__( self ):
      return self.seconds

   def __eq__( self, other ):
      # print "DEBUG: EpochObj.__eq__( %d, %d, %s )" % ( self.seconds, other.seconds, self.seconds == other.seconds )
      return self.seconds == other.seconds


class GidObj( RootObj ):

   def __init__( self, gid = None, name = None ):
      assert not gid or not name # can't have both
      assert gid or name         # must have one

      if gid:
         self.grp_obj = grp.getgrgid( gid )
      else:
         self.grp_obj = grp.getgrnam( name )

   def __eq__( self, other ):
      return self.grp_obj.gr_gid == other.grp_obj.gr_gid

   def __str__( self ):
      return self.grp_obj.gr_name

   def __int__( self ):
      return self.grp_obj.gr_gid


class UidObj( RootObj ):

   def __init__( self, uid = None, name = None ):
      assert not uid or not name # can't have both
      assert uid or name         # must have one

      if uid:
         self.pwd_obj = pwd.getpwuid( uid )
      else:
         self.pwd_obj = pwd.getpwnam( name )

   def __eq__( self, other ):
      # print "DEBUG: EpochObj.__eq__( %d, %d, %s )" % ( self.seconds, other.seconds, self.seconds == other.seconds )
      return self.pwd_obj.pw_gid == other.pwd_obj.pw_gid

   def __str__( self ):
      return self.pwd_obj.pw_name

   def __int__( self ):
      return self.pwd_obj.pw_gid


class HashMode( RootObj ):

   @staticmethod
   def get_len( hash_name ):
      return HASH_MODES[ hash_name ].hash_len

   @staticmethod
   def get_mode( hash_name ):
      return HASH_MODES[ hash_name ]

   def __init__( self, name, hash_obj ):

      hash_temp = hash_obj()
      hash_temp.update( "test data for computing hash lengths" )

      self.hash_name = name
      self.hash_obj  = hash_obj
      self.hash_len  = len( hash_temp.hexdigest() )

      del hash_temp

   def get_sum( self ):
      return self.hash_obj()


HASH_MODES = {
   "md5"       : HashMode( "md5",    hashlib.md5      ),
   "sha1"      : HashMode( "sha1",   hashlib.sha1     ),
   "sha224"    : HashMode( "sha224", hashlib.sha224   ),
   "sha256"    : HashMode( "sha256", hashlib.sha256   ),
   "sha384"    : HashMode( "sha384", hashlib.sha384   ),
   "sha512"    : HashMode( "sha512", hashlib.sha512   ),
}


class HashSum( RootObj ):

   def __init__( self, file_spec, hash_mode ):

      assert hash_mode

      # this defines the algorithm
      self.hash_mode    = hash_mode
      # this calculates the sum
      self.hash_sum     = self.hash_mode.get_sum()

      # read the file and calculate the sum
      with open( file_spec, "rb") as fd:
         while True:
            data = fd.read( 4096 )
            if not data:
               break
            self.hash_sum.update( data )

   def __str__( self ):
      return self.hash_sum.hexdigest()

   def __int__( self ):
      return len( self.hash_sum.hexdigest() )

   def __eq__( self, other ):
      return self.hash_sum.hexdigest() == other.hash_sum.hexdigest()

   def get( self ):
      return self.hash_sum.hexdigest()


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

   def __get_one( self ):
      if self.src:
         return self.src
      assert self.dst
      return self.dst

   def add_field( self, field ):
      self.fields.append( field )
      if field == "ftype":
         self.ftype_mismatch = True

   def has_both( self ):
      return self.src and self.dst

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

      if self.has_both():
         assert self.src.rel_path == self.dst.rel_path
         assert self.src.name     == self.dst.name

      return self.__get_one().get_relspec()

   def get_ftype( self ):

      if self.ftype_mismatch:
         return "----"

      return self.__get_one().ftype

   def get_fields( self ):
      return ",".join( self.fields )

   def scan( self ):
      if self.src and self.src.isdir():
         self.src.scan()
      if self.dst and self.dst.isdir():
         self.dst.scan()


   # TODO: this show method needs to be refactored

   def show( self, max_key_len ):

      fn = self.show_methods[ self.get_category() ]
      fn( max_key_len )

   @staticmethod
   def __show( obj, max_key_len ):
      print "%4s: %4s: %-*s (%s)" % ( obj.get_category(), obj.get_ftype(), max_key_len, obj.get_key(), obj.get_fields() )

   def __show_same( self, max_key_len ):
      self.__show( self, max_key_len )

   def __show_diff( self, max_key_len ):
      self.__show( self, max_key_len )

   def __show_src_only( self, max_key_len ):
      self.__show( self, max_key_len )

   def __show_dst_only( self, max_key_len ):
      self.__show( self, max_key_len )

   def __show_diff_type( self, max_key_len ):
      self.__show( self, max_key_len )


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

      self.max_key_len  = 0


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

      # and latch the max key length (for the show function)
      self.max_key_len = max( self.max_key_len, len( diff_key ) )

   # not currently used
   def __show( self ):

      for cat_name in CAT_ALL:
         cat = self.category[ cat_name ]
         for key in cat.keys():
            print "%8s: %s" % ( cat_name, key )

   def show_all( self ):

      keys = self.all.keys()
      keys.sort()

      for key in keys:
         diff_obj = self.all[ key ]
         diff_obj.show( self.max_key_len )


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

class DiffScanner( RootObj ):

   def __init__( self, src_input, dst_input, hash_mode, preserve = False ):

      assert isinstance( src_input, basestring )
      assert isinstance( dst_input, basestring )

      self.src_input = src_input
      self.src       = None         # placeholder
      self.dst_input = dst_input
      self.dst       = None         # placeholder
      self.hash_mode = hash_mode
      self.preserve  = preserve     # whether we preserve "same" entries

      self.scanned   = False
      self.diff_set  = None
      self.dir_queue = list()


   def run( self, show_func = None ):

      # disallow reuse of an object
      assert not self.scanned
      self.scanned   = True

      self.src = mk_entry( self.src_input, hash_mode = self.hash_mode )
      self.dst = mk_entry( self.dst_input, hash_mode = self.hash_mode )

      diff_obj = self.__compare( self.src, self.dst )

      if self.dst.isdir() and self.src.isdir():

         self.diff_set = DiffSet()
         self.__compare_children( self.src, self.dst )

      while len( self.dir_queue ):

         diff_obj = self.dir_queue.pop(0)
         self.__compare_children( *diff_obj.get_objs() )

      if show_func:
         show_func( self )


   def show_all( self ):
      self.diff_set.show_all()


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

   def __init__( self, inputs, hash_mode ):

      self.inputs       = inputs
      self.hash_mode    = hash_mode

      self.objs_idx     = dict()
      self.hash_idx     = dict()
      self.dir_queue    = list()

      self.max_rel_path  = 1


   def run( self, show_func = None ):

      # step 1 - iterate the inputs and create objects for each

      for file_spec in self.inputs:

         # split this input to get the root and name values
         root = os.path.dirname( file_spec )
         name = os.path.basename( file_spec )

         # make an entry for it
         obj = mk_entry( root, None, name, self.hash_mode )
         # and add the object to the list
         self.add_obj( obj )

      # step 2 - scan the directory queue to scan the tree

      while len( self.dir_queue ):

         obj = self.dir_queue.pop(0)
         obj.scan()

         if obj.entries:

            entry_names = obj.get_child_keys()
            for entry_name in entry_names:

               # get the child object
               child = obj.entries[ entry_name ]

               # and add it to the list
               self.add_obj( child )

            # this normally cleans up child objects, but it's superfluous as
            # we're keeping them all in the objs_idx dictionary anyways
            obj.reset()

      if show_func:
         show_func( self )


   def add_obj( self, obj ):

      # latch the longest rel_path length to format the column correctly
      if obj.rel_path:
         # print "DEBUG: %d, %s, %d" % (self.max_rel_path, obj.rel_path, len( obj.rel_path ) )
         self.max_rel_path  = max( self.max_rel_path, len( obj.rel_path ) )

      objs_key = obj.get_spec() 

      # add it to the name index
      assert not self.objs_idx.has_key( objs_key )
      self.objs_idx[ objs_key ] = obj

      # add it to the hash index
      if obj.hash_sum:

         hash_key = obj.hash_sum.get() 

         if not self.hash_idx.has_key( hash_key ):
            self.hash_idx[ hash_key ] = list()

         self.hash_idx[ hash_key ].append( obj )

      # if it's a directory, add it to the scan queue
      if obj.isdir():
         self.dir_queue.append( obj )


   def show_all( self ):

      names = self.objs_idx.keys()
      names.sort()

      for name in names:
         self.objs_idx[ name ].show( self.max_rel_path )


   def show_dups( self ):
      assert self.hash_mode

      names = self.hash_idx.keys()
      names.sort()

      for name in names:

         dups_list = self.hash_idx[ name ]
         assert len( dups_list )

         if len( dups_list ) > 1:

            print "\n%s: %s\n" % ( hash_mode.hash_name, name )

            for obj in dups_list:
               obj.show( self.max_rel_path, omit_hash = True )


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
   def compare_fields( src, dst, fields, check_name = False, check_hash = False ):

      assert src.__class__ == dst.__class__
      assert issubclass( src.__class__, BaseObj )

      if check_name:
         assert dst.name == src.name

      diff_obj = DiffObj( src, dst )

      for field in fields:

         if not BaseObj.compare_field( src, dst, field ):
            diff_obj.add_field( field )

      if check_hash:
         assert src.hash_mode == dst.hash_mode
         if not BaseObj.compare_field( src, dst, "hash_sum" ):
            diff_obj.add_field( "hash_sum" )

      return diff_obj

   def __init__( self, root, rel_path, name, ftype, hash_mode ):

      RootObj.__init__( self )

      self.root         = root
      self.rel_path     = rel_path
      self.name         = name
      self.name_desc    = name
      self.ftype        = ftype
      self.ftype_desc   = '-'
      self.hash_mode    = hash_mode

      self.stat_info    = get_stat( self.get_spec() )

      self.perm         = PermsObj( self.stat_info )
      self.uid          = UidObj( self.stat_info.st_uid )
      self.gid          = GidObj( self.stat_info.st_gid )
      self.size         = self.stat_info.st_size

      self.ctime        = EpochObj( self.stat_info.st_ctime ) # meta-data changed (created?)
      self.mtime        = EpochObj( self.stat_info.st_mtime ) # modified
      self.atime        = EpochObj( self.stat_info.st_atime ) # accessed

      self.hash_sum     = None

   def isdir( self ):
      return False

   def isfile( self ):
      return False

   def has_hash( self ):
      return self.hash_mode is not None

   def get_spec( self ):
      assert self.root
      return join_path( self.root, self.rel_path, self.name )

   def get_relspec( self ):
      assert self.name
      return join_path( self.rel_path, self.name )

   def get_rwx( self ):
      return self.ftype_desc + self.perm.get_rwx()

   def show( self, rel_path_size, omit_hash = False ):

      if self.hash_mode and not omit_hash:

         print "%4s: %5s/%s %4d/%-8s %4d/%-8s %8d %s %-*s %-*s %s" % (
            self.ftype,
            self.perm,
            self.get_rwx(),
            self.uid,
            self.uid,
            self.gid,
            self.gid,
            self.size,
            self.mtime,
            self.hash_mode.hash_len,
            self.hash_sum if self.hash_sum else '-',
            rel_path_size,
            self.rel_path if self.rel_path else ".",
            self.name_desc
            )
      else:
         print "%4s: %5s/%s %4d/%-8s %4d/%-8s %8d %s %-*s %s" % (
            self.ftype,
            self.perm,
            self.get_rwx(),
            self.uid,
            self.uid,
            self.gid,
            self.gid,
            self.size,
            self.mtime,
            rel_path_size,
            self.rel_path if self.rel_path else ".",
            self.name_desc
            )


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# file object

class FileObj( BaseObj ):

   fields = (
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

      diff_obj = BaseObj.compare_fields( src, dst, FileObj.fields, check_name, check_hash = src.has_hash() )
      return diff_obj

   def __init__( self, root, rel_path, name, hash_mode ):
      BaseObj.__init__( self, root, rel_path, name, IS_FILE, hash_mode )

      if hash_mode:
         self.hash_sum = HashSum( self.get_spec(), hash_mode )

   def isfile( self ):
      return True


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# link object

class LinkObj( BaseObj ):

   fields = (
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

      diff_obj = BaseObj.compare_fields( src, dst, LinkObj.fields, check_name )
      return diff_obj

   def __init__( self, root, rel_path, name, hash_mode ):
      BaseObj.__init__( self, root, rel_path, name, IS_LINK, hash_mode )

      self.link = os.readlink( self.get_spec() )

      self.name_desc    = self.name + ' -> ' + self.link
      self.ftype_desc   = 'l'


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# directory object

class DirObj( BaseObj ):

   fields = (
      "name",           # TODO: this should be controlled by the check_name parameter
      "ftype",
      "perm",
   )

   @staticmethod
   def compare( src, dst, check_name = False ):

      diff_obj = BaseObj.compare_fields( src, dst, DirObj.fields, check_name )
      return diff_obj

   def __init__( self, root, rel_path = None, name = None, hash_mode = None ):

      root              = os.path.abspath( root )

      BaseObj.__init__( self, root, rel_path, name, IS_DIR, hash_mode )

      self.entries      = None
      self.scanned      = False

      self.ftype_desc   = 'd'

      # print "DEBUG: dir: %s" % self.__class__

   def __mk_entry( self, entry_name ):
      # get the relative path of the entry
      rel_path = join_path( self.rel_path, self.name )
      # and make an entry for it
      return mk_entry( self.root, rel_path, entry_name, self.hash_mode )

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

def mk_entry( root, rel_path = None, name = None, hash_mode = None ):

   # canonicalize the root path
   abs_root    = os.path.abspath( root )
   # construct the file specification
   file_spec   = join_path( abs_root, rel_path, name )
   # get the file type
   ftype       = get_stat_type( file_spec )

   # print "DEBUG: making entry for '%s' of type '%s'" % ( file_spec, ftype )

   if DIR_ENTRY_CLASSES.has_key( ftype ):
      dentry_class   = DIR_ENTRY_CLASSES[ ftype ]
      return dentry_class( abs_root, rel_path, name, hash_mode )

   raise AssertionError



# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


# helper function for running the ListScanner, results are emitted by an
# unbound method

def _run_list( args = None, hash_mode = None, fn = None ):

   if not args:
      args = sys.argv[1:]
   if not len( args ):
      print "ERROR: specify one or more things to dump..."
      sys.exit(1)

   ls = ListScanner( args, hash_mode )
   ls.run( fn )


# top-level run commands, for processing command line modes

def run_test( args = None, hash_mode = None ):

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


def run_list( args = None, hash_mode = None ):

   _run_list( args, hash_mode, ListScanner.show_all )

def run_dups( args = None, hash_mode = None ):

   _run_list( args, hash_mode, ListScanner.show_dups )


def run_diff( args = None, hash_mode = None ):

   if not args:
      args = sys.argv[1:]
   if len( args ) != 2:
      print "ERROR: specify exactly 2 objects to compare"
      sys.exit()

   # get the args
   src, dst = args
   # and call the comparison function
   ds = DiffScanner( src, dst, hash_mode )
   ds.run( DiffScanner.show_all )

COMMANDS = {
   "TEST"   : run_test,
   "LIST"   : run_list,
   "DUPS"   : run_dups,
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
   mode.add_argument( "-d", "--diff",  action="store_const", const="DIFF",    dest="mode",       help="enables differencing mode"  )
   mode.add_argument( "-l", "--list",  action="store_const", const="LIST",    dest="mode",       help="enables list mode" )
   mode.add_argument( "-D", "--dups",  action="store_const", const="DUPS",    dest="mode",       help="enables bench testing" )
   mode.add_argument( "-t", "--test",  action="store_const", const="TEST",    dest="mode",       help="enables bench testing" )

   hash_name = parser.add_mutually_exclusive_group()
   hash_name.add_argument( "--md5",    action="store_const", const="md5",     dest="hash_name",  help="calc/compare md5 values" )
   hash_name.add_argument( "--sha1",   action="store_const", const="sha1",    dest="hash_name",  help="calc/compare sha1 values" )
   hash_name.add_argument( "--sha224", action="store_const", const="sha224",  dest="hash_name",  help="calc/compare sha224 values" )
   hash_name.add_argument( "--sha256", action="store_const", const="sha256",  dest="hash_name",  help="calc/compare sha256 values" )
   hash_name.add_argument( "--sha384", action="store_const", const="sha384",  dest="hash_name",  help="calc/compare sha384 values" )
   hash_name.add_argument( "--sha512", action="store_const", const="sha512",  dest="hash_name",  help="calc/compare sha512 values" )

   parser.add_argument( "--debug",     action="store_true",  default=False,                      help="dump debugging information" )
   parser.add_argument( "--verbose",   action="store_true",  default=False,                      help="include extra information, where applicable" )

   parser.add_argument( "scopes", nargs=argparse.REMAINDER )

   args = parser.parse_args()

   DEBUG    = args.debug
   VERBOSE  = args.verbose

   hash_mode = None
   if args.hash_name:
      hash_mode      = HashMode.get_mode( args.hash_name )

   if args.mode == "DUPS" and not hash_mode:
      parser.error( "-D|--dups requires a hashing mode" )

   if VERBOSE:
      print "mode=%s"      % args.mode
      print "debug=%s"     % args.debug
      print "verbose=%s"   % args.verbose
      print "scopes=%s"    % args.scopes

   fn = COMMANDS[ args.mode ]
   fn( args.scopes, hash_mode )


# vim: syntax=python si
