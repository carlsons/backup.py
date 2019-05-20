#! /usr/bin/python

import hashlib
import sys


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

#  __  __    _    ___ _   _
# |  \/  |  / \  |_ _| \ | |
# | |\/| | / _ \  | ||  \| |
# | |  | |/ ___ \ | || |\  |
# |_|  |_/_/   \_\___|_| \_|
# TAGS: MAIN

if __name__ == "__main__":

   if len( sys.argv ) == 1:
      print "BARF! give me a file to read!"
      sys.exit(1)

   f = open( sys.argv[1], "rb")
   h = hashlib.md5()

   while True:
      d = f.read( 4096 )
      if not d:
         break
      h.update( d )
      sys.stdout.write( '.' )

   print ""

   print h.hexdigest()


