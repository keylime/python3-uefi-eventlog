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
        description ="run PCR validation on binary logs"
    )
    parser.add_argument(
        '-d',
        '--dir',
        help='directory where raw logs are kept')
    parser.add_argument(
        '-p',
        '--parsed',
        default='parsed-tpm2-tools-5.5/1stcut',
        help='directory name for parsed files')

    args = parser.parse_args()
    compare_dir(args.dir, args.parsed)

def compare_dir (dirname, parseddir):
    binarylogs = glob.glob(dirname + '/*/*.bin')
    print()
    print("+------------------------------+-------+-------+")
    print("|    log file                  |# PCRs | #err  |")
    print("+------------------------------+-------+-------+")

    total_pcrs = 0
    total_errs = 0
    for binarylog in binarylogs:
        logname = os.path.basename(binarylog)
        logdir = os.path.dirname(binarylog)
        reflogname = logdir + '/' + parseddir + '/' + logname.replace('.bin', '.yml')
        try:
            with open (reflogname, 'r') as fp:
                reflog = yaml.safe_load(fp)
                if 'pcrs' not in reflog: raise Exception("PCRs not available")
                refpcrs = reflog['pcrs']
        except Exception as e:
            print("|%-30.30s|%7d|%7d| reference log: %s"%(logname, 0, 0, str(e)))
            continue

        try:
            with open (binarylog, 'rb') as fp:
                buffer = fp.read()
                testlog = eventlog.EventLog(buffer, len(buffer))
                testpcrs = testlog.pcrs()

                tested_pcrs = 0
                error_pcrs = 0

                for key in refpcrs:
                    for pcrno in refpcrs[key]:
                        refvalue = f'{refpcrs[key][pcrno]:x}'
                        tested_pcrs += 1
                        try:
                            testvalue = testpcrs[key][pcrno]
                        except:
                            error_pcrs += 1
                            continue
                        if refvalue != testvalue.hex():
                            if refvalue != testvalue.hex()[1:]:
#                                print(refvalue, '!=', testvalue.hex())
                                error_pcrs += 1

            print("|%-30.30s|%7d|%7d|"%(logname, tested_pcrs, error_pcrs))
            total_pcrs += tested_pcrs
            total_errs += error_pcrs

        except Exception as e:
            print("|%-30.30s| %s"%(logname, str(e)))
            

    print("+------------------------------+-------+-------+")
    print("|     Totals:                  |%7d|%7d|"%(total_pcrs, total_errs))
    print("+------------------------------+-------+-------+")

    if total_errs > 0:
        print()
        print("FAILED (PCR values mismatch reference)")
        exitcode=1
    else:
        print()
        print("SUCCESS")
        exitcode=0
    exit(exitcode)
        
main()
