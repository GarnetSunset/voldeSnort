from bs4 import BeautifulSoup
from shutil import copyfile
import os
import re
import requests
import sys
from six.moves.urllib.request import urlopen

emergURL = 'https://rules.emergingthreats.net/open-nogpl/snort-2.9.0/rules/'
excludes = ['version.txt']
ruleList = []
noscrape = 0
ticker = 0
totalRules = 0

verNum = urlopen("https://rules.emergingthreats.net/open-nogpl/snort-2.9.0/version.txt").read()
if os.path.isfile("version.txt"):
    curVer = open("version.txt").read()
    if verNum == curVer:
        print("Congrats! You're on the latest version! One less nightmare to worry about.")
        noscrape = 1
else:
    with open("version.txt",'wb') as f:
        f.write(urlopen("https://rules.emergingthreats.net/open-nogpl/snort-2.9.0/version.txt").read())
        f.close()
        curVer = open("version.txt").read()
        noscrape = 0
if noscrape == 0:
    owd = os.getcwd()
    if not os.path.exists("comparison"):
        os.makedirs("comparison")
    os.chdir("comparison")
    filelist = [ f for f in os.listdir(".") if f.endswith(".rules") ]
    for f in filelist:
        os.remove(f)
    os.chdir(owd)
    if not os.path.exists("extras"):
        os.makedirs("extras")
    os.chdir("extras")
    filelist = [ f for f in os.listdir(".") if f.endswith(".rules") ]
    for f in filelist:
        os.remove(f)
    os.chdir(owd)

    if not os.path.exists("comparison"):
        os.makedirs("comparison")
    requestRec = requests.get(emergURL)
    soup = BeautifulSoup(requestRec.content, 'lxml')
    rulesOnly = soup.findAll(text=re.compile(r"\.rules"))

    for x in rulesOnly:
        x.encode("utf-8")
        ruleList.append(str(x))
    print("\nThere are " + str(len(ruleList)) + " rules in the list.\n\nDownloading them to the comparison directory now.\n")
    while totalRules != len(ruleList) - 1:
        with open('comparison/' + ruleList[totalRules],'wb') as f:
            f.write(urlopen(emergURL+ruleList[totalRules]).read())
            f.close()
        totalRules += 1
    print("Downloaded\n\nNow Beginning Replacement...\n")

    with open("threshold_misconfigs.txt") as f:
        for line in f:
            findStop = line.index("|")
            firstLine = line[:findStop]
            replaceLine = line[findStop:-1]
            firstLine = firstLine.replace('|','').replace('"','')
            replaceLine = replaceLine.replace('|','').replace('"','')
            for dname, dirs, files in os.walk("comparison"):
                for fname in files:
                    fpath = os.path.join(dname, fname)
                    with open(fpath) as f:
                        s = f.read()
                    s = s.replace(firstLine, replaceLine)
                    with open(fpath, "w") as f:
                        f.write(s)

    print("Done checking\n\nNow searching for extras.\n")

    if not os.path.exists("extras"):
        os.makedirs("extras")

    for dname, dirs, files in os.walk("comparison"):
        for fname in files:
            fpath = os.path.join(dname, fname)
            with open(fpath) as f:
                for line in f:
                    if "threshold" in line:
                        ticker += 1
                        with open('extras/'+fname+".extras.rules", "w") as f:
                            f.write(line)
    if(ticker > 0):
        print("The last threshold listings are in the extras folder!\n")

if os.path.isfile(verNum.rstrip() + "-emerging-threats.rules"):
    os.remove(verNum.rstrip() + "-emerging-threats.rules")

print("Concatenating all files into one file named \"" + verNum + "-emerging-threats.rules\"")

for dname, dirs, files in os.walk("comparison"):
    for fname in files:
        fpath = os.path.join(dname, fname)
        with open(verNum.rstrip() + "-emerging-threats.rules", "a+") as outfile:
            with open(fpath, "rb") as infile:

                outfile.write(infile.read())

print("Concatenation done!")
