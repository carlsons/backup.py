#! /usr/bin/zsh


run_test()
{
   echo ""
   echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
   echo $@
   echo ""

   $@
   rc=$?

   echo ""
   echo "TEST DONE! (rc=$rc)"

}

run_test ./backup.py -l *
run_test ./backup.py -l --md5 *
run_test ./backup.py -D --md5 *
run_test ./backup.py -d dir_src dir_dst
run_test ./backup.py -d --md5 dir_src dir_dst

# vim: syntax=sh
