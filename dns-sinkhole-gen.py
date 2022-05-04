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

url_useragent = (
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0"
)
url_timeout = 60
filepath = "./unbound/"

timestamp_long = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

unbound_datafile = "blacklist.conf"
unbound_tempfile = unbound_datafile + ".tmp"

domains_blacklists = [
    {
        "name": "My custom blocklist",
        "url": "file:///home/" + os.getcwd() + "/lists/blacklist.txt",
    },
    {
        "name": "StevenBlack blocklist",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    },
    {
        "name": "YouTube ads (kboghdady)",
        "url": "https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/black.list",
    },
    {
        "name": "Ads and tracking extended (lightswitch05)",
        "url": "https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt",
    },
    # {
    #     "name": "Facebook (lightswitch05)",
    #     "url": "https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/facebook-extended.txt",
    # },
    # {
    #     "name": "Tracking aggressive (lightswitch05)",
    #     "url": "https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/tracking-aggressive-extended.txt",
    # },
]

domains_whitelists = [
    {
        "name": "My custom whitelist",
        "url": "file://" + os.getcwd() + "/lists/whitelist.txt",
    }
]

failedlists = []


def filewrite(filepath, datafile, string, operationmode, closefile):
    with open(os.path.join(filepath, datafile), operationmode) as f:
        f.write(string)
    if closefile is True:
        f.close()


def getlist(domainlist, timeout):
    if not domainlist is None:
        try:
            print("Processing list:\t\t" + domainlist["name"])
            request = URL.Request(
                domainlist["url"], headers={"User-Agent": url_useragent}
            )
            return np.array(
                URL.urlopen(request, timeout=timeout).read().decode("utf-8").split("\n")
            )

        except KeyboardInterrupt:
            exit(0)

        except:
            print("Data retrieval failed:\t\t" + domainlist["url"] + "\n")
            failedlists.append(domainlist["name"])
            pass


def fetchdomaindata(dataset):
    fetched_data = set()
    if not dataset is None:
        for line in dataset:
            if (
                not re.search(".*:.*", line)
                and not re.search("[\[|\]]", line)
                and not re.search("^.*#", line)
                and not re.search(".*localhost.*", line)
                and not re.search("\slocal$", line)
                and not re.search("^$", line)
                and re.search("[a-z]+", line)
            ):
                line = re.sub(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ \t]+", "", line)

                # Windows EOL last character substitution, corrects misformatted line variable
                line = re.sub("[\n]?\r$", "", line)

                if not re.match("^$", line):
                    fetched_data.add(line)

        if len(set(fetched_data)) == 0:
            print("\t\t\t\tNo domain entries found\n")

        return fetched_data


filewrite(filepath, unbound_datafile, "", "w", True)

if domains_whitelists:
    for whitelist in domains_whitelists:
        whitelist_dataset = getlist(whitelist, url_timeout)

    whitelist_fetched_data = fetchdomaindata(whitelist_dataset)
else:
    whitelist_fetched_data = set()

for blacklist in domains_blacklists:
    blacklist_dataset = getlist(blacklist, url_timeout)

    if not blacklist_dataset is None:
        for line in fetchdomaindata(blacklist_dataset):

            if not line in whitelist_fetched_data:

                if re.search("^\.", line):
                    pass
                elif re.search("\*", line):
                    pass
                else:
                    unbound_line = 'local-zone: "' + line + '" always_refuse'

                if not unbound_line is None:
                    filewrite(filepath, unbound_tempfile, unbound_line + "\n", "a", False)


def parseuniqlines(filepath, tempfile, outfile):
    uniqdata = set()
    with open(os.path.join(filepath, outfile), "a") as f:
        for line in open(os.path.join(filepath, tempfile), "r"):
            if not line in uniqdata:
                f.write(line)
                uniqdata.add(line)
        f.close()
    os.remove(os.path.join(filepath, tempfile))
    print("----------------------------------------")
    print(
        "Added "
        + str(len(set(uniqdata)))
        + " unique domains to the sinkhole file "
        + filepath
        + outfile
    )
    print("DNS sinkhole file " + filepath + outfile + " generated successfully.")


parseuniqlines(filepath, unbound_tempfile, unbound_datafile)

if len(failedlists) > 0:
    print("Warning: could not get data for the following blocklists:\n")
    for i in range(len(failedlists)):
        print("\t" + failedlists[i])
    print("")
