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
        description ="compare event logs and test logs"
    )
    parser.add_argument(
        '-d',
        '--dir',
        help='directory where raw and yaml logs are kept')
    parser.add_argument(
        '-p',
        '--parsed',
        default='parsed-tpm2-tools-5.5/fixed',
        help='directory name for parsed files')

    args = parser.parse_args()
    compare_dir(args.dir, args.parsed)

def binary2json(binarylogfile: str):
    with open (binarylogfile, 'rb') as fp:
        buffer = fp.read()
        testlogbin = eventlog.EventLog(buffer, len(buffer))
        testlog = json.dumps(testlogbin, default=lambda o: o.to_json(), sort_keys=True)
        return testlog

def compare_log (jsonreflog, jsontestlog, failedeventtypes={}):
    reflog = json.loads(jsonreflog)['events']
    reflen = len(reflog)
    testlog = json.loads(jsontestlog)
    errors = 0
    for idx in range(0, reflen):
        if reflog[idx] != testlog[idx]:
            errors += 1
            failedeventtypes[reflog[idx]['EventType']] = True

    return (reflen, errors, failedeventtypes)

def compare_dir (dirname, parseddir):
    binarylogs = glob.glob(dirname + '/*/*.bin')
    failedeventtypes = {}
    etotal=0
    evttotal=0
    print("Eventlog parsing failure summary")
    print()
    print("+------------------------------+-------+-------+-------+----")
    print("|    log file                  | #Evts | #Fail |  Pct. | msg.")
    print("+------------------------------+-------+-------+-------+----")
    for binarylog in binarylogs:
        logdir  = os.path.dirname(binarylog)
        logname = os.path.basename(binarylog)
        
        # step 1: read the reference log
        try:
            reflogname = logdir + '/' + parseddir + '/' + logname.replace('.bin', '.json')
            with open (reflogname, 'r') as fp:
                reflog = fp.read()
                reflen = 1
        except Exception as e:
            etotal+= 1
            evttotal += 1
            print("|%-30.30s|%7d|%7d|%6.2f%%|reflog fail: %s"%(logname, 1, 1, 100.0, str(e)))
            continue

        # step 2: try the python log parser and translate to JSON
        try:
            jsontestlog = binary2json(binarylog)
        except Exception as e:
            err = reflen
            etotal+= err
            evttotal += err
            print("|%-30.30s|%7d|%7d|%6.2f%%|testlog fail: %s"%(logname, reflen, err, 100.0*err/reflen, str(e)))
            continue

        # step 3: compare both JSON logs
        try:
            [reflen, err, failedeventtypes] = compare_log(reflog, jsontestlog, failedeventtypes)
        except:
            err = reflen

        etotal+= err
        evttotal += reflen
        print("|%-30.30s|%7d|%7d|%6.2f%%|"%(logname, reflen, err, 100.0*err/reflen))

    print("+------------------------------+-------+--------+------+")
    print("|     Totals:                  |%7d|%7d|%6.2f%%|"%(evttotal, etotal, 100.0*etotal/evttotal))
    print("+------------------------------+-------+--------+------+")

    if etotal/evttotal > 0.01:
        print()
        print("FAILED (error rate > 1%)")
        exitcode=1
    else:
        print()
        print("SUCCESS (error rate <= 1%)")
        exitcode=0

    print()
    print("Failed event types")
    print("------------------")
    for key in failedeventtypes.keys():
        print("%-20s"%(key))
    exit(exitcode)
        
main()
