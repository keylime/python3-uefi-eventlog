#!/usr/bin/env python3

from eventlog import eventlog
import argparse
import json
import yaml
import time
import glob
import os

def main():
    parser = argparse.ArgumentParser(
        description ="run validation on binary logs"
    )
    parser.add_argument(
        '-d',
        '--dir',
        help='directory where raw logs are kept')

    args = parser.parse_args()
    compare_dir(args.dir)

def compare_dir (dirname):
    binarylogs = glob.glob(dirname + '/*/*.bin')
    print()
    print("+------------------------------+-------+-------+")
    print("|    log file                  | #evts | #fail |")
    print("+------------------------------+-------+-------+")
    evttotal=0
    etotal=0
    for binarylog in binarylogs:
        logname = os.path.basename(binarylog)
        with open (binarylog, 'rb') as fp:
            buffer = fp.read()
            try:
                testlog = eventlog.EventLog(buffer, len(buffer))
                faillist = testlog.validate()
                why = ''
                if len(faillist) > 0: why = faillist[0][3]
                print("|%-30.30s|%7d|%7d|%s"%(logname, len(testlog), len(faillist), why))
                evttotal += len(testlog)
                etotal += len(faillist)
            except Exception as e:
                print("|%-30.30s|%7d|%7d|%s"%(logname, 1, 1, str(e)))
                evttotal += 1
                etotal += 1
                pass
    print("+------------------------------+-------+--------+")
    print("|     Totals:                  |%7d|%7d|"%(evttotal, etotal))
    print("+------------------------------+-------+--------+")

    if etotal > 0:
        print()
        print("FAILED (not all logs self-validated)")
        exitcode=1
    else:
        print()
        print("SUCCESS (all good logs self-validated)")
        exitcode=0
    exit(exitcode)
        
main()
