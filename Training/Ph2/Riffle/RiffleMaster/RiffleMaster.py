#!/usr/bin/python

import os
from subprocess import *
import time
import shutil

def preparse_mft(extractedPath,toolsPath):
    # Parsing and loading mft
    cwd = os.getcwd()
    mftPath = os.path.join(extractedPath,"mft")
    mftDumpedPath = os.path.join(mftPath,"mftdumped")
    if not os.path.exists(mftDumpedPath):
        os.makedirs(mftDumpedPath)
    print "\nParsing mft first pass"
    for root,dirs,files in os.walk(mftPath):
        if root == mftPath:
            for f in files:
                print "\t" + f
                check_output([os.path.join(toolsPath,"mftdump.exe"),
                              "--output="+os.path.join(mftDumpedPath,f),
                              os.path.join(mftPath,f)])

def start():
    cwd = os.getcwd()
    t = time.strftime("%Y-%m-%d_%H%M%S",time.localtime())
    dbname = os.path.join(cwd,"Databases",t+".db3")
    srcpath = os.path.join(cwd,"SourceData")
    pypath = "C:\\Python27\\python.exe"
    extractedPath = os.path.join(cwd,"Extracted",t)
    if not os.path.exists(extractedPath):
        os.makedirs(extractedPath)
    pluginsPath = os.path.join(cwd,"Plugins")
    toolsPath = os.path.join(cwd,"Tools")
    logsPath = os.path.join(cwd,"Logs",t)
    if not os.path.exists(logsPath):
        os.makedirs(logsPath)
    
    print "\nInserting data into " + os.path.basename(dbname)

    # Unpacking 7zip files
    print "\nUnpacking Riffle 7zip files"
    for root,dirs,files in os.walk(srcpath):
        for f in files:
            try:
                print "Extracting riffle archive file: ", f
                check_output([os.path.join(cwd,"Tools","7za.exe"), "x", \
                              "-phunt_4_malware", "-o"+extractedPath, \
                              os.path.join(srcpath,f)])
            except Exception,e:
                print "Error extracting riffle archive file " + f
                print str(e)
                continue

    # Parsing and loading data
    for root,dirs,files in os.walk(pluginsPath):
        for f in files:
            if f == "mft2db.py":
                preparse_mft(extractedPath,toolsPath)
            print "\nParsing " + os.path.splitext(os.path.basename(f))[0][:-3]
            check_output([pypath,os.path.join(pluginsPath,f),"-c", \
                          dbname,logsPath,extractedPath])


if __name__ == "__main__":
    start()
