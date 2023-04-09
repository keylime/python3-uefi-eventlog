#!/bin/bash

export parsedir=parsed-tpm2-tools-5.5

# Initial preparation of parsed event logs using the Intel TPM2 tool kit.
# All Intel error messages are ignored. Only the parsed output is recorded.

export LD_LIBRARY_PATH=/usr/local/lib

function step1() {
    echo "Step 1: pass through all event logs, process with tpm2_eventlog"
    for file in */*.bin
    do
	fname=$(basename ${file})
	yamlname=${fname/.bin/.yml}
	dir=$(dirname ${file})
	mkdir -p ${dir}/${parsedir}/1stcut
	tpm2_eventlog --eventlog-version=2 ${file} > ${dir}/${parsedir}/1stcut/${yamlname} 2>/dev/null
	exitcode=$?
#	printf "%-30.30s %2d\n" ${fname} ${exitcode}
    done
}


# step 2: automatic YAML fixes

# mostly this is about fixing the way tpm2_eventlog expresses
# multi-line strings and includes ending 0es in strings.

# NOTE the "moklist" rule below is specifically for a red hat event
# log that tpm2_eventlog parses to include an invalid UTF-16
# character. This makes everything, from yq to jq to grep to sed,
# choke on the string, except when sed removes and replaces it
# completely.

function step2() {
    echo "Step 2: remove string quote problems from YAML"
    for file in */${parsedir}/1stcut/*.yml
    do
	fname=$(basename ${file})
	dir=$(dirname ${file})
	mkdir -p ${dir}/../fixed
	fixedname=${dir}/../fixed/${fname//yml/json}
	cat ${file} | \
	    sed '/^      "MokList\\0/c\      MokList' | \
	    sed 's/"\(.*\)\\0"$/\1/' | \
	    sed 's/      "\(.*\)"$/      \1/' | \
	    sed 's/\\t/\t/g' | \
	    sed "s/\\\'/\'/g" | yq -r . > ${fixedname}
    done
}

# step 3: manual fixes

function step3() {
    true
}


step1
step2
