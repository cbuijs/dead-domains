#!/usr/bin/env python3
# Needs Python 3.5 or newer!

# MODULES ################################################################################

# Make sure modules can be found
import sys
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Standard/Included modules
import os, os.path, socket, time, shelve #, traceback

# Use requests module to test websites
import requests

# Use module regex instead of re, much faster less bugs
import regex


# VARIABLES ##############################################################################

if sys.argv[1:]:
    domains_file = sys.argv[1]
else:
    print('Usage: {0} <domains-file>'.format(sys.argv[0]))
    sys.exit(1)

### Regexes
isdomain = regex.compile('(?=^.{1,252}[a-z]$)(^((?!-)[a-z0-9_-]{0,62}[a-z0-9]\.)*(xn--[a-z0-9-]{1,59}|[a-z]{2,63})$)', regex.I)

# CODE ###################################################################################

if __name__ == '__main__':
    '''Main beef'''
    try:
        f = open(domains_file, 'r')
        lines = f.read().splitlines()
        f.close()

    except BaseException as err:
        print('ERROR: Unable to open/read/process file \"{0}\" - {1}'.format(domains_file, err))
        sys.exit(1)

    count = 0
    for line in lines:
        count += 1
        entry = regex.split('#', regex.split('\s+', line)[0].strip().lower())[0]
        if entry and isdomain.search(entry):
            print('\n\nProcessing domain \"{0}\"'.format(entry))
        else:
            print('\n\nWARNING [Line #{0}]: Invalid domain \"{1}\"'.format(count, entry))

    sys.exit(0)

# <EOF>
