"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-11-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        sec_evt2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     12-28-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-02-01 04:52:27 -0800 (Wed, 01 Feb 2012) $
$Revision: 1343 $
$Author: mspohn $
*/
/////////////////////////////////////////////////////////////////////////////
/*==========================================================================
 * Copyright (C) 2012, by Michael G. Spohn.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
/*==========================================================================*/
 *  event2db.py
 *  This script loads an XML event log output file into a database for analysis.
 *  It was created using Python 2.7.
 *==========================================================================*/
"""
import sqlite3
import os
import subprocess
import argparse
import logging # Log levels: DEBUG INFO WARNING ERROR CRITICAL
import xml.etree.ElementTree as et

"""
Function List
==========================================
main():                                     Script entry point
CreateEvtLogFileList(evt_file_or_dir):      Creates a list of security event log files to process
VerifyEvtFileOrDir(full_path):              Verifies the event log or dir of event logs is valid
OpenOrCreateDB(db_name, user, pwd):         Opens or creates a database
OpenSQLiteDB(db_path):                      Opens or creates an SQLite3 database
IsEvtLogFile(path):                         Verifies a file is a security event file
LoadEvents(evt_file, con):                  Loads event log data into a database
GetCommandLineArgs():                       Processes command line arguments
"""

"""
PSLogList output fields
=======================
Line_No
Source
Evt_Log
Evt_Type
Hostname
DateTime
EvtID
User
Description
"""

# Event table schema for SQLite
sqlite_event_table_schema = """
CREATE TABLE events (ID INTEGER PRIMARY KEY AUTOINCREMENT,
LogType TEXT NOT NULL,
Hostname TEXT NOT NULL,
LogRecNo INTEGER NOT NULL,
SourceName TEXT NOT NULL,
DateGenerated TEXT NOT NULL,
EventID INTEGER NOT NULL,
SID TEXT,
Description TEXT);
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strEvtFileorDir = ''
g_logPath = ''

# Other globals
S_QUOTE = '\''
COMMA = ','
g_bIsDir = False
g_conSQLite = None
g_conMySQL = None
g_LogLevel = logging.INFO
g_ParseErrors = None
g_InsertErrors = None

def main():
    global g_ParseErrors
    global g_InsertErrors

    # Get command line args
    #logging.debug('+++ Getting command line args.')
    if GetCommandLineArgs() != 0:
        return -1

    # Set log levels
    logging.basicConfig(format='%(asctime)s %(message)s', \
                        filename=os.path.join(g_logPath,'eventlog2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'eventlog2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'eventlog2db_insert_errors.txt'), 'w')

    # Verify passed in event log file or dir exists
    if VerifyEvtFileOrDir(g_strEvtFileorDir) != 0:
        logging.error('--- File or directory ' + g_strEvtFileorDir + 'does not exist.') 
        print 'File or directory ', g_strEvtFileorDir, 'does not exist.'
        return -1

    # Open or create the event database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of evt logs to process
    lstEvtFileList = CreateEvtLogFileList(g_strEvtFileorDir)
    logging.debug('+++ CreateEvtLogFileList(' + g_strEvtFileorDir + ')')
    if len(lstEvtFileList) == 0:
         logging.error('--- No event log files were found to process.')
         print 'No event log files were found.'
         return -1
    if len(lstEvtFileList) == 1: 
        print '+++ There is', str(len(lstEvtFileList)), 'event log to process...'
    if len(lstEvtFileList) > 1: 
        print '+++ There are', str(len(lstEvtFileList)), 'event logs to process...'

    outPath = os.path.join(g_strEvtFileorDir,"xml")
    if not os.path.exists(outPath):
        os.makedirs(outPath)
    deleteFile = True
    for afile in lstEvtFileList:
        if g_bSQLiteDB == True:
            afileNoExt = os.path.splitext(os.path.basename(afile))[0]
            evtxFile = os.path.join(outPath,afileNoExt+".evtx")
            textFile = os.path.join(outPath,afileNoExt+".txt")
            logging.debug('SQLite3 LoadEvents(' + g_strEvtFileorDir + '\\' + afile + ')')
            try:
                subprocess.check_output(["wevtutil","epl",afile,evtxFile,"/lf:true","/ow:true"])
            except:
                evtxFile = afile
                deleteFile = False
            try:
                output = subprocess.check_output(["wevtutil","qe",evtxFile,"/lf:true","/f:text"],
                                                 stderr=subprocess.STDOUT,shell=True)
            except subprocess.CalledProcessError,e:
                output = e.output
            except:
                logging.error('--- LoadEvents() - potentially corrupted evt_file ' + afile + '.')
                continue
            f = open(textFile,'w')
            f.write(output)
            f.close()
            print '+++ Loading event file', textFile, 'into SQLite3 database...'
            LoadEvents(textFile, g_conSQLite)
            if deleteFile:
                os.remove(evtxFile)
            deleteFile = True

    logging.info('+++ Closing database.')
    print '+++ Loading event log files completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of event logs to process
string evt_file_or_dir - path to event log file or directory

Returns:
list of evt filenames, -1 if fatal error
"""
def CreateEvtLogFileList(evt_file_or_dir):

    logging.debug('+++ CreateEvtLogFileList(' + evt_file_or_dir + ')')
        
    # Sanity checks
    if len(evt_file_or_dir) == 0:
        logging.error('CreateEvtLogFileList(evt_file_or_dir) - evt_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(evt_file_or_dir) == False:
        logging.error('CreateEvtLogFileList(evt_file_or_dir) - evt_file_or_dir param path does not exist.')
        return -1
    
    lstEvtFiles = []

    # Verify a single evt log file
    if os.path.isfile(evt_file_or_dir):
        res = IsEvtLogFile(evt_file_or_dir)
        if res != -1 and res != False:
            lstEvtFiles.append(evt_file_or_dir)
        else:
            logging.info('--- ' + evt_file_or_dir + 'is not an event log file.')
            print '--- ', evt_file_or_dir, ' is not an event log file.'
        return lstEvtFiles

    # Verify a dir of evt log files
    dir_list = os.listdir(evt_file_or_dir)
    for afile in dir_list:
        res = IsEvtLogFile(evt_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstEvtFiles.append(evt_file_or_dir + '\\' + afile)
        else:
            print '---', evt_file_or_dir + '\\' + afile, 'is not an event log file.'
    
    return lstEvtFiles


"""
Verify event log file or directory
Parameters:
string full_path - path to event log file or directory

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyEvtFileOrDir(full_path):
    global g_bIsDir

    if len(full_path) == 0:
        return -1
    
    if os.path.exists(full_path) == False:
        return -1

    if os.path.isdir(full_path) == True:
        g_bIsDir = True

    return 0

"""
Open or create database
Parameters:
string db_name - name of the database
string user    - user name of db if required
string pwd     - user pwd of db if required

Returns:
0 if database if opened, -1 if error
"""
def OpenOrCreateDB(db_name, user, pwd):
    # Sanity check
    if len(db_name) == 0:
        logging.error('--- OpenOrCreateDB(db_name, user, pwd): - db_name parameter is not valid.')
        print '--- Database name is not valid.'
        return -1

    if g_bSQLiteDB == True:
        if OpenSQLiteDB(db_name) == 0:
            return 0
        else:
            return -1


"""
Open/create an SQLite3 database.
Parameters:
string db_path - name of SQLite database

Returns:
0 if successfully opened or created, -1 if error
"""
def OpenSQLiteDB(db_path):
    global g_conSQLite

    # Sanity check
    if len(db_path) == 0:
        logging.error('--- OpenSQLiteDB(db_path) - db_path parameter is not valid.')
        return -1
    
    db_exists = os.path.exists(db_path)
    
    if g_bCreateDB == False and db_exists == False:
        logging.error('--- SQLite database does not exist and create flag is false.')
        print '--- SQLite database does not exist and create flag is false.'
        return -1

    if db_exists == False:
        try:
            g_conSQLite = sqlite3.connect(db_path)
            g_conSQLite.execute(sqlite_event_table_schema)
            return 0
        except:
            logging.error('--- Error creating events table in SQLite3 database.')
            print '--- Error creating event table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the event table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS events')
            g_conSQLite.execute(sqlite_event_table_schema)
            return 0
        except:
            logging.error('--- Error dropping events table from SQLite3 database.')
            print '--- Error dropping events table from SQLite3 database.'
            return -1

    # Make sure event table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM events;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating events table in SQLite3 database.')
        g_conSQLite.execute(sqlite_event_table_schema)

    return 0


"""
Verifies a file is a Windows event log
Returns:
    -1 if there was an error
    False if file is not an event log file
    'evt' if file is an older event log file
    'evtx' if file is Vista+ log file
"""
def IsEvtLogFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
    
    isDirectory = False
    evt = False
    evtx = False
        
    # Confirm we have a valid event log file
    # Must have a valid filename
    if not path.lower().endswith('.evt'):
        return -1

def insertEvent(logType, eventRecordID, fields, cur):
    #fields = hostname,source,timestamp,eventID,sid,description
    try:    
        ins_string = 'INSERT INTO events values(NULL,'
        ins_string += S_QUOTE + logType + S_QUOTE + COMMA
        ins_string += S_QUOTE + fields[0] + S_QUOTE + COMMA
        ins_string += eventRecordID + COMMA
        ins_string += S_QUOTE + fields[1] + S_QUOTE + COMMA
        ins_string += S_QUOTE + fields[2] + S_QUOTE + COMMA
        ins_string += fields[3] + COMMA
        ins_string += S_QUOTE + fields[4] + S_QUOTE + COMMA
        ins_string += S_QUOTE + fields[5] + S_QUOTE + ')'
            
        cur.execute(ins_string)
    except Exception,e:
        logging.error('--- Error inserting event into database:')
        logging.error(ins_string)
        g_InsertErrors.write(ins_string + '\n')
        return 1
    return 0


def parseEvent(event):
    hostname = ""
    source = ""
    timestamp = ""
    eventID = ""
    sid = ""
    description = ""
    details = ""
    desc = False
    for line in event:
        if desc == True:
            description += line + "\t"
        elif line.startswith("Computer:"):
            hostname = line[10:]
        elif line.startswith("Source:"):
            source = line[8:]
        elif line.startswith("Date:"):
            timestamp = line[6:]
        elif line.startswith("Event ID:"):
            eventID = line[10:]
        elif line.startswith("User:"):
            sid = line[6:]
        elif line.startswith("Description:"):
            desc = True
    description = description.replace("\'","")
    description = description.replace("\"","")
    return hostname,source,timestamp,eventID,sid,description


"""
Load events into events table
Parameters:
string evt_file          - Event log xml to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadEvents(evt_file, con):

    # Sanity checks
    if len(evt_file) == 0:
        logging.error('--- LoadEvents() - evt_file parameter is empty.')
        return -1
    if os.path.exists(evt_file) == False:
        logging.error('--- LoadEvents() - evt_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadEvents() - con parameter is not valid.')
        return -1
    cur = con.cursor()
    logType = os.path.basename(evt_file[evt_file.rfind("_")+1:-4])

    f = open(evt_file,'r')
    rows = f.read().split("\n")
    f.close()
    eventRecordID = -1
    ins_count = 0
    err_count = 0
    row_count = 0
    event = []
    for row in rows:
        row = row.strip()
        if row == "":
            continue
        elif row.startswith("Event["):
            row_count += 1
            if eventRecordID != -1:
                try:
                    fields = parseEvent(event)
                    ins_count += insertEvent(logType, eventRecordID, fields, cur)
                except Exception,e:
                    g_ParseErrors.write(str(event) + '\n')
                    err_count += 1
                event = []
            eventRecordID = row[6:-2]
        elif eventRecordID != -1:
            event.append(row)
    try:
        fields = parseEvent(event)
        ins_count += insertEvent(logType, eventRecordID, fields, cur)
    except Exception,e:
        g_ParseErrors.write(str(event) + '\n')
        err_count += 1

    con.commit()
    cur.close()
    
    print '+++', row_count, 'total rows processed.'
    print '---', err_count, 'parse errors.'
    print '---', ins_count, 'database insertion errors.'  
    
    return 0

"""
Process command line args
Parameters: None
Returns: 0 if success, -1 if invalid command line args
"""
def GetCommandLineArgs():

    global g_strDBName
    global g_bCreateDB
    global g_bEmptyDB
    global g_bSQLiteDB
    global g_strUserName
    global g_strUserPwd
    global g_strEvtFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import event logs into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('evtlog_file_or_dir', help = 'event log file or directory of event logs.')

    try:
        results = parser.parse_args()
    except IOError, msg:
        return -1

    g_logPath = results.logpath
    g_strDBName = results.db_name
    g_bCreateDB = results.create_db
    g_bEmptyDB = results.empty_db
    g_bSQLiteDB = results.sqlite_db
    g_strUserName = results.user_name
    g_strUserPwd = results.user_pwd
    g_strEvtFileorDir = os.path.join(results.evtlog_file_or_dir,"logs","evt")

    return 0

if __name__ == "__main__":
    main()




