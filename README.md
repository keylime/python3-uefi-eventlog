# python3-uefi-eventlog

A pure python library to parse and process UEFI measured boot
logs. Written as an alternative to `tpm2_eventlog` in the
https://github.com/tpm2-software/tpm2-tools project; the ultimate goal
is to provide a python-native way to parse measured boot logs.

## Getting started

The implementation is in `eventlog/eventlog.py`. Absent a packaging
system (TBD) copy the file into your project and import it. Then use
it as below to produce JSON output:

```
    import eventlog

    ...

    with open (<name of binary event log file>, 'rb') as fp:
        buffer = fp.read()
        evlog = eventlog.EventLog(buffer, len(buffer))

	...
	# dump the event log in JSON form
        print(json.dumps(evlog, default=lambda o: o.toJson(), indent=4))

	...
	# print out the event validation status
	print(evlog.validate())

	...
	# print out the expected value of all PCRs in the TPM device
	print(evlog.getpcrs())

```

## Design principle

The library is designed to be a drop-in replacement in Keylime's event
log processing. The JSON output generated is identical to that
produced by `tpm2-tools/tpm2_eventlog`, with two exceptions:

* We did not see fit to reproduce certain `tpm2_eventlog` bugs and
  problems; we also want to isolate ourselves from the output's
  dependency on the `tpm2-tools` release in use.

* `efivar` parsing of the output should be an optional flag for the
  event log parser.

## Directory structure

* The event log parser itself is in the `eventlog` directory.

* Reference logs for testing are in the `testlog` directory. Each
  binary event log is accompanied by the YAML formatted output
  produced by `tpm2_eventlog`.

* Testing code and reference usage code are in the `testing` directory.

## Testing and CI

Testing of this repository is arranged against a known set of binary
event logs, comparing the output of the `eventlog` library against a
"known good" reference. Each run is scored by the number of events
where output diverges from the reference.

As reference, we use the *hand-corrected* `tpm2_eventlog` parsed text
output for the same binaries.

## Outstanding list of TODOs

* While the eventlog library is able to generate the TPM PCR outputs,
  that output is not being tested today. (TEST MISSING)

* Only a subset of digest algorithms supported by the TCG
  specification is implemented; namely, `sha1`, `sha256`,
  `sha384`. This subset covers all event logs we have seen so far, but
  this also means that most likely there exists an event log somewhere
  that the python library cannot handle today (FEATURE MISSING)

* The `efivar` based enrichment feature is currently disabled and not
  tested (FEATURE MISSING).

* There is no support for packaging yet (FEATURE MISSING)


## Implementation details

Note the use of a JSON "transformer" function (`toJson`) -- every
non-natively serializable class in the `eventlog` package implements
this function. The design purpose is to allow the eventlog parser to
collect information into a custom class hierarchy with data members
corresponding to each event type as defined by TCG, and then use the
`toJson()` member function to create JSON compatible output.


## Documentation and references:

* Reference documentation from the (Trusted Computing
  Group)[https://trustedcomputinggroup.org/resource/tpm-library-specification]:

  * Trusted Platform Module Library, Part 1 (commands), Part 2 (structures)
  * TCG Guidance on Integrity Measurements and Event Log Processing
  * (TCG PC Client Platform Firmware Profile Specification)[https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf]

* Other implementations:
  * (Intel TPM2 software)[https://github.com/tpm2-software]
  * (IBM's TPM 2.0 TSS library)[https://sourceforge.net/projects/ibmtpm20tss/]
  * Patrick Uiterwijk's (rust event parser library)[https://github.com/puiterwijk/uefi-eventlog-rs]
  * [https://github.com/whooo/eventlogs]
  