#!/usr/bin/env python3
# Needs Python 3.5 or newer!
'''
Todo:
- Do something smart with the outcomes, create an "ACTIVE" and "INACTIVE" list
- Faster/Own WHOIS processor
'''

# MODULES ################################################################################

# Make sure modules can be found
import sys
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Standard/Included modules
import os, os.path, time

# Use requests module to test websites
import requests

# Use module regex instead of re, much faster less bugs
import regex

# Whois
import pythonwhois
from datetime import datetime

# Dns
from dns import resolver
dnsres = resolver.Resolver()
dnsres.nameservers = ['1.1.1.1', '1.0.0.1']
dnsres.lifetime = 3
dnsres.timeout = 3

# VARIABLES ##############################################################################

# Filename
if sys.argv[1:]:
    domains_file = sys.argv[1]
else:
    print('Usage: {0} <domains-file>'.format(sys.argv[0]))
    sys.exit(1)

# Headers used for request
headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'}

# Whois cache
whois_cache = dict()


# REGEXES ################################################################################

isdomain = regex.compile('(?=^.{1,252}[a-z]$)(^((?!-)[a-z0-9_-]{0,62}[a-z0-9]\.)*(xn--[a-z0-9-]{1,59}|[a-z]{2,63})$)', regex.I)


# CODE ###################################################################################

def sigint_handler(signal, frame):
    '''Interrupted'''
    print
    sys.exit(1)


def dom_sort(domlist):
    '''Domain Sort'''
    newdomlist = list()
    for y in sorted([x.split('.')[::-1] for x in domlist]):
        newdomlist.append('.'.join(y[::-1]))

    return newdomlist


def has_web_site(domain):
    '''Check if we can request a website/page'''
    # Try HTTP
    try:
        r = requests.get('http://' + domain, timeout=3, headers=headers, allow_redirects=True)
    except:
        r = False

    # Try HTTPS
    if r is False:
        try:
            r = requests.get('https://' + domain, timeout=3, headers=headers, allow_redirects=True)
        except:
            r = False

    if r and r.status_code in (100, 101, 200, 201, 202, 203, 204, 205, 206):
        return True

    return False


def is_dns_resolvable(domain):
    '''Check if DNS resolvable'''
    try:
        answers = dnsres.query(domain)
    except:
        answers = False

    if answers:
        return True

    return False


def is_whois_active(domain):
    '''Check if domain is expired'''
    testdomain = domain
    rc = None
    while testdomain and testdomain.count('.') > 0:
        print('-- WHOIS-Domain: {0}'.format(testdomain))

        if testdomain in whois_cache:
            return whois_cache[testdomain]

        try:
            w = pythonwhois.get_whois(testdomain, True)
        except:
            w = False

        if w:
            if 'raw' in w and str(w['raw']).upper().find('BLACKLIST') > 0:
                print('---- WHOIS-Blacklisted: We are blacklisted for lookups for {0}'.format(testdomain))
                rc = None
                break

            elif 'expiration_date' in w:
                expdate = int(w['expiration_date'][0].timestamp())
                now = int(time.time())
                if expdate >= now:
                    rc = True
                    break

            elif ('status' in w) and (str(w['status']).upper() in ('ACTIVE', 'INACTIVE')):
                status = w['status']
                if status.upper() == 'ACTIVE':
                    rc = True
                    break
                else:
                    rc = False
                    break

            else:
                rc = False
                break


        if testdomain.find('.') == -1:
            break
        else:
            testdomain = testdomain[testdomain.find('.') + 1:]

    whois_cache[testdomain] = rc
    return rc


if __name__ == '__main__':
    '''Main beef'''
    try:
        f = open(domains_file, 'r')
        lines = dom_sort(f.read().splitlines())
        f.close()

    except BaseException as err:
        print('ERROR: Unable to open/read/process file \"{0}\" - {1}'.format(domains_file, err))
        sys.exit(1)

    count = 0

    for line in lines:
        count += 1
        entry = regex.split('#', regex.split('\s+', line)[0].strip().lower())[0]
        if entry and isdomain.search(entry):
            score = 0
            print('\n\nProcessing domain \"{0}\"'.format(entry))
            if is_whois_active(entry) is not False:
                print('-- WHOIS: Active')
                score += 25
                if is_dns_resolvable(entry):
                    print('-- DNS: Resolvable')
                    score += 50
                    if has_web_site(entry):
                        print('-- WEB: Has HTTP/HTTPS connectivity')
                        score += 25
                    else:
                        print('-- WEB: NO HTTP/HTTPS connectivity')
                else:
                    print('-- DNS: NOT Resolvable')
            else:
                print('-- WHOIS: INACTIVE')

            print('---- SCORE: {0}%'.format(score))

            #if score >= 75:
            #    # Write to ACTIVE FILE
            #else:
            #    # Write to INACTIVE FILE

        else:
            print('\n\nInvalid line [{0}]: {1}'.format(count, line))

    sys.exit(0)

# <EOF>
