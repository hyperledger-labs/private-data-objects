<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Scheme Extensions Tests #

This directory contains several tests for the Scheme extensions defined
for the Gipsy contract interpreter.

The tests require a stock tinyscheme interpreter and source, and a
shared library with the Scheme extensions defined.

## Install TinyScheme ##

Tinyscheme can be installed with apt:
`sudo apt install tinyscheme`

Source for TinyScheme is available from
[sourceforge.net](https://sourceforge.net/projects/tinyscheme/files/).

For testing purposes, you cannot compile against the tinyscheme package
included with the `PrivateDataObjects` repository; the structure of the
scheme interpreter extension interface has changed.

## Build the Extensions ##

The Scheme extensions can be built as a TinyScheme extension library by
building `pcontract.so` in the Gipsy interpreter directory. Note that to
build `pcontract.so` you need to change the TINYSCHEME macro to point to
the TinyScheme source directory. For example:

`make TINYSCHEME=~/dev/packages/tinyscheme-1.41/ pcontract.so`

## Run the Tests ##

From the tests directory, the tests can be run with the following
command:

`LD_LIBRARY_PATH=.. tinyscheme -1 test.scm`

The file `test.scm` loads the environment, aes, ecdsa and rsa tests.
