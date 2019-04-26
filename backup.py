#! /usr/bin/python

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# import needed modules

import sys
import os
import stat

import collections

import traceback
import pprint

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
   IS_UNKNOWN
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

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

class DiffEntry( RootObj ):

   def __init__( self, old, new ):

      # call the base class constructor
      RootObj.__init__( self )

      self.old = old
      self.new = new
      self.fields = []

   def add_field( self, field ):
      self.fields.append( field )

   def has_diffs( self ):
      return len( self.fields )

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# base/helper classes

class DirEntryPerms( RootObj ):

   def __init__( self, stat_info ):
      RootObj.__init__( self )
      self.val   = stat.S_IMODE( stat_info.st_mode )

   def __str__( self ):
      return "%s" % oct( self.val )

   def __eq__( self, other ):
      return self.val == other.val


class DirEntry( RootObj ):

   @staticmethod
   def compare_field( old, new, field ):

      old_val = old.__dict__[ field ]
      new_val = new.__dict__[ field ]

      is_equal = False
      if old_val == new_val:
         is_equal = True

      print "DEBUG: %s.%s: '%s' %s= '%s'" % ( old.__class__, field, old_val, ( "=" if is_equal else "!" ), new_val )

      return is_equal

   @staticmethod
   def compare( old, new, fields, check_name = False ):

      assert old.__class__ == new.__class__
      assert issubclass( old.__class__, DirEntry )

      if check_name:
         assert old.name == new.name

      print "DEBUG: comparing %s: '%s' -> '%s'" % ( old.ftype, old.name, new.name )

      diff_obj = DiffEntry( old, new )

      for field in fields:

         if not DirEntry.compare_field( old, new, field ):
            diff_obj.add_field( field )

      return diff_obj

   def __init__( self, parent, name, ftype ):

      RootObj.__init__( self )

      self.parent       = parent
      self.name         = name

      self.stat_info    = get_stat( self.get_spec() )
      self.ftype        = ftype

      self.perm         = DirEntryPerms( self.stat_info )

      # print "DEBUG: entry: %s" % self.__class__

   def isdir( self ):
      return False

   def get_spec( self ):
      return os.path.join( self.parent, self.name )


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

# derived classes for different types of directory entries

class FileObj( DirEntry ):

   def __init__( self, parent, name ):
      DirEntry.__init__( self, parent, name, IS_FILE )

      # print "DEBUG: file: %s" % self.__class__

class LinkObj( DirEntry ):

   def __init__( self, parent, name ):
      DirEntry.__init__( self, parent, name, IS_LINK )

      # print "DEBUG: link: %s" % self.__class__

      # TODO: read the link and add a "points_to" member...

class DirObj( DirEntry ):

   compare_fields = (
      "name",           # TODO: this should be controlled by the check_name parameter
      "ftype",
      "perm",
   )







   @staticmethod
   def compare( old_dir, new_dir, check_name = False ):

      assert old_dir.isdir()
      assert new_dir.isdir()

      diff_obj = DirEntry.compare( old_dir, new_dir, DirObj.compare_fields, check_name )

      if old_dir.scanned and new_dir.scanned:

         # TODO: don't think we want to do this here!
         DirObj.compare_children( old_dir, new_dir )

      return diff_obj








   @staticmethod
   def compare_children( old_dir, new_dir ):

      assert old_dir.isdir()
      assert old_dir.scanned
      assert new_dir.isdir()
      assert new_dir.scanned

      # get the keys (i.e.: the names) of the entries from both old and new
      old_set     = set( old_dir.entries.keys() )
      new_set     = set( new_dir.entries.keys() )
      # find the intersection, i.e.: the entry names that appear in both the old and new
      union       = old_set.union( new_set )
      intersect   = old_set.intersection( new_set )
      # now subtract out the intersection to get what's unique in both
      old_only    = old_set - intersect
      new_only    = new_set - intersect

      pprint.pprint( old_set )
      pprint.pprint( new_set )
      pprint.pprint( union )
      pprint.pprint( intersect )
      pprint.pprint( old_only )
      pprint.pprint( new_only )



      # TODO: LEFT OFF HERE!!! need to scan the directory entries


      for name in intersect:

         old = old_dir.entries[ name ]
         new = new_dir.entries[ name ]

         compare_objects( old, new, True )








   def __init__( self, parent, name = None ):

      parent            = os.path.abspath( parent )

      if not name:
         name           = os.path.basename( parent )
         parent         = os.path.dirname(  parent )

      DirEntry.__init__( self, parent, name, IS_DIR )

      self.entries      = None
      self.scanned      = False

      # print "DEBUG: dir: %s" % self.__class__

   def _mk_entry( self, entry_name ):
      file_spec         = os.path.join( self.get_spec(), entry_name )
      return mk_entry( file_spec )

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
               self.entries[ entry_name ] = self._mk_entry( entry_name )

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

def mk_entry( file_spec ):

   # split it up so we can get the parent
   dir_name    = os.path.dirname( file_spec )
   base_name   = os.path.basename( file_spec )

   # convert the input to an absolute specification
   dir_spec    = os.path.abspath( dir_name )

   # get the file type
   ftype       = get_stat_type( file_spec )

   # print "DEBUG: making entry for '%s' of type '%s'" % ( file_spec, ftype )

   if DIR_ENTRY_CLASSES.has_key( ftype ):
      dentry_class   = DIR_ENTRY_CLASSES[ ftype ]
      return dentry_class( dir_spec, base_name )

   raise AssertionError


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


#  __        _____  ____  _  __  ___ _   _   ____  ____   ___   ____ ____  _____ ____ ____
#  \ \      / / _ \|  _ \| |/ / |_ _| \ | | |  _ \|  _ \ / _ \ / ___|  _ \| ____/ ___/ ___|
#   \ \ /\ / / | | | |_) | ' /   | ||  \| | | |_) | |_) | | | | |  _| |_) |  _| \___ \___ \
#    \ V  V /| |_| |  _ <| . \   | || |\  | |  __/|  _ <| |_| | |_| |  _ <| |___ ___) |__) |
#     \_/\_/  \___/|_| \_\_|\_\ |___|_| \_| |_|   |_| \_\\___/ \____|_| \_\_____|____/____/


# TODO: these comparison fields need to be moved into their respective classes
# like what's in DirObj

def compare_files( old_file, new_file, check_name = False ):

   print "DEBUG: comparing files"

def compare_links( old_link, new_link, check_name = False ):

   print "DEBUG: comparing links"

DIR_ENTRY_COMPARATORS = {
   IS_DIR   : DirObj.compare,
   IS_FILE  : compare_files,
   IS_LINK  : compare_links

   # TODO: what about all of the other file types

}

def compare_objects( old_obj, new_obj, check_name ):

   print """
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
DEBUG: COMPARING OBJECTS

old: %s
new: %s
""" % ( old_obj.get_spec(), new_obj.get_spec() )

   if old_obj.get_spec() == new_obj.get_spec():
      print "ERROR: comparing an object to itself"
      sys.exit()

   if old_obj.ftype != new_obj.ftype:
      print "ERROR: objects are *NOT* the same type"
      sys.exit()

   print "DEBUG: objects *ARE* the same type '%s'" % old_obj.ftype

   # at this point we know the ftypes are the same, so we can use either one
   ftype = old_obj.ftype

   if DIR_ENTRY_COMPARATORS.has_key( ftype ):
      compare_fn = DIR_ENTRY_COMPARATORS[ ftype ]
      return compare_fn( old_obj, new_obj, check_name )

   raise AssertionError







def compare_entries( old_entry, new_entry, check_name = False ):

   # use the factory to instantiate objects for each entry

   old_obj = mk_entry( old_entry )
   old_obj.scan()

   new_obj = mk_entry( new_entry )
   new_obj.scan()

   compare_objects( old_obj, new_obj, check_name )



# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

#   _____ _____ ____ _____    ____ ___  ____  _____
#  |_   _| ____/ ___|_   _|  / ___/ _ \|  _ \| ____|
#    | | |  _| \___ \ | |   | |  | | | | | | |  _|
#    | | | |___ ___) || |   | |__| |_| | |_| | |___
#    |_| |_____|____/ |_|    \____\___/|____/|_____|
#  TAGS: TEST CODE

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

def test_module():

   args = sys.argv[1:]

   if len( args ):
      dump_objs( args )
   else:
      print "ERROR: specify one or more things to discover..."


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

if __name__ == "__main__":

   # test_module()

   args = sys.argv[1:]

   if len( args ) != 2:
      print "ERROR: specify exactly 2 objects to compare"
      sys.exit()

   # get the args
   old, new = args
   # and call the comparison function
   compare_entries( old, new )





