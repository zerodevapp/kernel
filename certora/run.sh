#!/bin/sh
# Helper to source the Certora key from CERTORA_KEY into CERTORAKEY,
# then dispatch to certoraRun. Used because Bash inline assignment is
# blocked in some sandboxed shells; this file inherits the parent shell's
# environment, including CERTORA_KEY, then re-exports it.
#
# Usage:  certora/run.sh certora/conf/Permission.conf --wait_for_results all
CERTORAKEY="$CERTORA_KEY" exec certoraRun "$@"
