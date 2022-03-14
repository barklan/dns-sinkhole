#!/bin/env python3

# Copyright 2019 Pekka Helenius

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

########################################

# Simple DNS sinkhole file generation for DNSCrypt & pdnsd servers
# Block DNS query resolutions for specific network domains

########################################

import os
import re
import readline
import signal
import sys
import time

import numpy as np
import urllib.request as URL

from datetime import datetime
from socket import timeout

########################################

url_useragent     = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'
url_timeout       = 60
filepath          = '/tmp/'

#timestamp_short   = datetime.now().strftime('%Y-%m-%d')
timestamp_long    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

####################

pdnsd_datafile    = 'pdnsd.sinkhole'
pdnsd_tempfile    = pdnsd_datafile + '.tmp'

pdnsd_fileheader  = "// Auto-generated list, build date " + timestamp_long + "\n// No addresses of these domains must be resolved" + "\n\n"

pdnsd_outmessage  = ("Move it to /etc/ folder and add the following configuration setting in /etc/pdnsd.conf:\n\n" + \
"//Blacklisted domains\ninclude { file = \"/etc/" + pdnsd_datafile + "\"; }\n\n--------------------\nRestart pdnsd by issuing command 'systemctl restart pdnsd'\n\nYou may need to delete your pdnsd.cache file before the list rules apply.\n")

####################

dnscrypt_datafile   = 'dnscrypt.cloaking.txt'
dnscrypt_tempfile   = dnscrypt_datafile + ".tmp"

dnscrypt_fileheader = "# Auto-generated list, build date " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n# No addresses of these domains must be resolved" + "\n\n"

dnscrypt_outmessage = ("Move it to /etc/dnscrypt-proxy/ and add the following configuration setting in\n/etc/dnscrypt-proxy/dnscrypt-proxy.toml:\n\n" + \
"cloaking_rules = '/etc/dnscrypt-proxy/" + dnscrypt_datafile + "'\n\n--------------------\nRestart dnscrypt-proxy by issuing command 'systemctl restart dnscrypt-proxy'\n")

########################################

domains_blacklists = [
    # {
    #   'name': 'My custom blocklist',
    #   'url':  'file:///home/' + os.environ['USER']  + '/dns-sinkhole.txt'
    # },
    {
      'name': 'StevenBlack blocklist',
      'url':  'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
    },
    {
      'name': 'YouTube ads (kboghdady)',
      'url':  'https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/black.list'
    },
    {
      'name': 'Ads and tracking extended (lightswitch05)',
      'url':  'https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt'
    },
    # {
    #   'name': 'Facebook (lightswitch05)',
    #   'url':  'https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/facebook-extended.txt'
    # },
    # {
    #   'name': 'Tracking aggressive (lightswitch05)',
    #   'url':  'https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/tracking-aggressive-extended.txt'
    # },
]

########################################
# Exclude these pre-blacklisted domains from the final DNS sinkhole blacklist

domains_whitelists = [
   {
     'name': 'My custom whitelist',
     'url':  'file://' + os.getcwd()  + '/lists/whitelist.txt'
   }
]

########################################

failedlists = []

##########
def filewrite(filepath, datafile, string, operationmode, closefile):
    with open(os.path.join(filepath, datafile),operationmode) as f:
        f.write(string)
    if closefile is True:
      f.close()

##########
def getlist(domainlist,timeout):
    if not domainlist is None:
        try:
            print("Processing list:\t\t" + domainlist['name'])
            request = URL.Request(domainlist['url'],headers={'User-Agent': url_useragent})
            return np.array(URL.urlopen(request, timeout=timeout).read().decode('utf-8').split('\n'))

        except KeyboardInterrupt:
            exit(0)

        except:
            print("Data retrieval failed:\t\t" + domainlist['url'] + "\n")
            failedlists.append(domainlist['name'])
            pass

##########
def fetchdomaindata(dataset):
    fetched_data = set()
    if not dataset is None:
        for line in dataset:
            if not re.search('.*:.*', line) \
            and not re.search('[\[|\]]', line) \
            and not re.search('^.*#', line) \
            and not re.search('.*localhost.*', line) \
            and not re.search('\slocal$', line) \
            and not re.search('^$', line) \
            and re.search('[a-z]+', line):
                line = re.sub(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ \t]+','',line)

                # Windows EOL last character substitution, corrects misformatted line variable
                line = re.sub('[\n]?\r$','',line)

                if not re.match('^$',line):
                    fetched_data.add(line)

        if len(set(fetched_data)) == 0:
            print("\t\t\t\tNo domain entries found\n")

        return fetched_data

########################################
# DNS sinkhole file headers

filewrite(filepath, pdnsd_datafile, pdnsd_fileheader, 'w', True)
filewrite(filepath, dnscrypt_datafile, dnscrypt_fileheader, 'w', True)

####################
# Download and parse white/blocklists

##########
if domains_whitelists:
    for whitelist in domains_whitelists:
        whitelist_dataset = getlist(whitelist, url_timeout)

    whitelist_fetched_data = fetchdomaindata(whitelist_dataset)
else:
    whitelist_fetched_data = set()


##########
for blacklist in domains_blacklists:
    blacklist_dataset = getlist(blacklist, url_timeout)

    if not blacklist_dataset is None:
        for line in (fetchdomaindata(blacklist_dataset)):

            if not line in whitelist_fetched_data:

                if re.search('^\.', line):
                    pdnsd_line    = "neg { name=*" + line + "; types = domain; }"
                elif re.search('\*', line):
                    pdnsd_line    = "neg { name=" + line + "; types = domain; }"
                else:
                    pdnsd_line    = "rr { name=" + line + "; a=0.0.0.0; }"
                    dnscrypt_line = line + " " + "0.0.0.0"

                filewrite(filepath, pdnsd_tempfile, pdnsd_line + '\n', 'a', False)

                if not dnscrypt_line is None:
                    filewrite(filepath, dnscrypt_tempfile, dnscrypt_line + '\n', 'a', False)

####################
# Parse generated list, get only unique lines and write to final file
def parseuniqlines(filepath, tempfile, outfile, outmessage):
  uniqdata = set()
  with open(os.path.join(filepath, outfile),'a') as f:
      for line in open(os.path.join(filepath, tempfile),'r'):
          if not line in uniqdata:
              f.write(line)
              uniqdata.add(line)
      f.close()
  os.remove(os.path.join(filepath, tempfile))
  print("----------------------------------------")
  print("Added " + str(len(set(uniqdata))) + " unique domains to the sinkhole file " + filepath + outfile)
  print("DNS sinkhole file " + filepath + outfile + " generated successfully.")
  print(outmessage)

parseuniqlines(filepath, pdnsd_tempfile, pdnsd_datafile, pdnsd_outmessage)
parseuniqlines(filepath, dnscrypt_tempfile, dnscrypt_datafile, dnscrypt_outmessage)

####################
# Inform user about failed DNS blocklist downloads
if len(failedlists) > 0:
    print("Warning: could not get data for the following blocklists:\n")
    for i in range(len(failedlists)):
        print("\t" + failedlists[i])
    print("")
