Acknowledgements
==

These are measured boot logs from various systems, collected by
various people. Thanks to James E J Bottomley (IBM), Ken A Goldman
(IBM), Patrick Uiterwijk (RH) and others for providing samples; thanks
to Mike Spreitzer (IBM) for systematically collecting them.

If you are reading this and are in a giving mood, please consider
opening a PR on this repository with your contribution. I will gladly
add it to the test suite.

Event logs processing
--

At the moment my personal workstation has `tpm2-tools` version 5.5
installed on it, compiled from git a few weeks ago.

`prepare.sh` works through all binary event logs and creates "1st cut"
approximations of the YAML files for comparison purposes.

-- George Almasi


