"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-02-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        mfeaplog2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-12-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-02-01 04:52:40 -0800 (Wed, 01 Feb 2012) $
$Revision: 1345 $
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
 *  mfeaplog2db.py
 *  This script loads McAfee Access Protection logs into a database for analysis.
 *  It was created using Python 2.7.
 *  The only external python module required is MySQL-Python (http://mysql-python.sourceforge.net/)
  *==========================================================================*/
"""
import sqlite3
import os
import subprocess
import argparse
import logging # Log levels: DEBUG INFO WARNING ERROR CRITICAL 

"""
Function List
==========================================
main():                                        Script entry point
CreateAPSFileList(g_strMFEAPLogFileorDir):     Creates a list of McAfee AP log files to process
VerifyMFEAPFileOrDir(full_path):               Verifies MFE AP log file or directory exist
OpenOrCreateDB(db_name, user, pwd):            Opens or creates a database
OpenSQLiteDB(db_path):                         Opens or creates an SQLite3 database
IsMFEAPFile(path):                             Verifies a file is a McAfee AP log file
LoadMFEAPFiles(g_strMFEAPLogFileorDir, con):   Loads a McAfee AP log into a database
GetCommandLineArgs():                          Processes command line parms
"""

"""
McAfee AP log Fields
=================
date
time
action
user
module
file
rule
action
"""

# Database schemas
sqlite_mfeaplog_table_schema = """
Create Table mfeaplogs (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Hostname TEXT NOT NULL,
Date TEXT NOT NULL,
Time TEXT NOT NULL,
Action TEXT,
User TEXT,
Module TEXT,
File TEXT,
Rule TEXT,
Final_Action TEXT);
"""

mysql_mfeaplog_table_schema = """
Create Table mfeaplogs (ID INT NOT NULL AUTO_INCREMENT,
Hostname TEXT NOT NULL,
Date TEXT NOT NULL,
Time TEXT NOT NULL,
Action TEXT,
User TEXT,
Module TEXT,
File TEXT,
Rule TEXT,
Final_Action TEXT,
PRIMARY KEY (ID));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strMFEAPLogFileorDir = ''
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
                        filename=os.path.join(g_logPath,'mfeaplog2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'mfeaplog2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'mfeaplog2db_insert_errors.txt'), 'w')
    
    # Verify passed in MFE AP log file or dir exists
    if VerifyMFEAPFileOrDir(g_strMFEAPLogFileorDir) != 0:
        logging.error('--- File or directory ' + g_strMFEAPLogFileorDir + 'does not exist.') 
        print 'File or directory ', g_strMFEAPLogFileorDir, 'does not exist.'
        return -1

    # Open or create the database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of MFE AP logs to process
    lstMFEAPLogFileList = CreateAPFileList(g_strMFEAPLogFileorDir)
    logging.debug('+++ CreateAPFileList(' + g_strMFEAPLogFileorDir + ')')
    if len(lstMFEAPLogFileList) == 0:
         logging.error('--- No MFE AP log files were found to process.')
         print 'No MFE AP log files were found.'
         return -1
    if len(lstMFEAPLogFileList) == 1: 
        print '+++ There is', str(len(lstMFEAPLogFileList)), 'MFE AP log files to process...'
    if len(lstMFEAPLogFileList) > 1: 
        print '+++ There are', str(len(lstMFEAPLogFileList)), 'MFE AP log files to process...'

    for afile in lstMFEAPLogFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadEvents(' + g_strMFEAPLogFileorDir + '\\' + afile + ')')
            print '+++ Loading MFE AP log file', afile, 'into SQLite3 database...'
            LoadMFEAPFiles(afile, g_conSQLite)

    logging.info('+++ Closing database.')
    print '+++ Loading of MFE AP log files completed...'

    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of MFE AP log files to process
string MFEAPLog_file_or_dir - path to MFE AP file or directory of MFE AP log files

Returns:
list of MFE AP log filenames, -1 if fatal error
"""
def CreateAPFileList(MFEAPLog_file_or_dir):

    logging.debug('+++ CreateAPFileList(' + MFEAPLog_file_or_dir + ')')
        
    # Sanity checks
    if len(MFEAPLog_file_or_dir) == 0:
        logging.error('CreateAPFileList(MFEAPLog_file_or_dir) - MFEAPLog_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(MFEAPLog_file_or_dir) == False:
        logging.error('CreateAPFileList(MFEAPLog_file_or_dir) - MFEAPLog_file_or_dir param path does not exist.')
        return -1
    
    lstMFEAPLogFiles = []

    # Verify a single MFE AP log file
    if os.path.isfile(MFEAPLog_file_or_dir):
        res = IsMFEAPFile(MFEAPLog_file_or_dir)
        if res != -1 and res != False:
            lstMFEAPLogFiles.append(MFEAPLog_file_or_dir)
        else:
            logging.info('--- ' + MFEAPLog_file_or_dir + 'is not a MFE AP log file.')
            print '--- ', MFEAPLog_file_or_dir, ' is not a MFE AP log file.'
        return lstMFEAPLogFiles

    # Verify a dir of MFE AP log files
    dir_list = os.listdir(MFEAPLog_file_or_dir)
    for afile in dir_list:
        res = IsMFEAPFile(MFEAPLog_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstMFEAPLogFiles.append(MFEAPLog_file_or_dir + '\\' + afile)
        else:
            print '---', MFEAPLog_file_or_dir + '\\' + afile, 'is not an MFE AP log file.'
    
    return lstMFEAPLogFiles


"""
Verify MFE AP log file or directory
Parameters:
string full_path - path to MFE AP log file or directory of MFE AP log files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyMFEAPFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_mfeaplog_table_schema)
            return 0
        except:
            logging.error('--- Error creating mfeaplogs table in SQLite3 database.')
            print '--- Error creating mfeaplogs table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the MFE AP table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS mfeaplogs')
            g_conSQLite.execute(sqlite_mfeaplog_table_schema)
            return 0
        except:
            logging.error('--- Error dropping mfeaplogs table from SQLite3 database.')
            print '--- Error dropping mfeaplogs table from SQLite3 database.'
            return -1

    # Make sure mfeaplogs table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM mfeaplogs;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating mfeaplogs table in SQLite3 database.')
        g_conSQLite.execute(sqlite_mfeaplog_table_schema)
        
    return 0

"""
Verifies a file is a MFE AP log file
Returns:
    -1 if there was an error
    False if file is not a MFE AP log file
"""
def IsMFEAPFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid MFE AP log file
    # No structure to log file. We look for the fields we know must be in the log
    if path.lower().find('mcafeeav_accessprotectionlog') < 0:
        return -1

    mfeaplog_file = None
    try:
        mfeaplog_file = file(path, 'r')
        for x in range(10):
            sig = mfeaplog_file.readline()
            a_line = sig.split('\t')
            if len(a_line) and a_line[0].count('/') == 2 and a_line[1].count(':') == 2:
                mfeaplog_file.close()
                return True
    except:
        mfeaplog_file.close()
        return -1

    mfeaplog_file.close()
    return False

"""
Load MFE AP log fileinto mfeaplogs table
Parameters:
string mfeaplog_file     - MFE AP log file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadMFEAPFiles(mfeaplog_file, con):
    global g_ParseErrors
    global g_InsertErrors
    row_count = 0

    # Sanity checks
    if len(mfeaplog_file) == 0:
        logging.error('--- LoadMFEAPFiles() - mfeaplog_file parameter is empty.')
        return -1
    if os.path.exists(mfeaplog_file) == False:
        logging.error('--- LoadMFEAPFiles() - mfeaplog_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadMFEAPFiles() - con parameter is not valid.')
        return -1
    
    # Open the MFE AP log file
    a_file = file(mfeaplog_file, 'r')
    if a_file == None:
        logging.error('--- LoadMFEAPFiles() - error opening mfeaplog_file ' + mfeaplog_file + '.')
        return -1

    hostname = os.path.basename(mfeaplog_file)
    if hostname.find('_') > 0:
        hostname = hostname.split('_')[0]
    
    cur = con.cursor()
    row_count = 0
    err_count = 0
    ins_count = 0

    while 1:
        x = a_file.readline()
        if len(x) == 0:
            break

        # Ignore the junk
        if len(x) == 1:
            continue
  
        # Strip ', " , \n
        x = x.replace("'", '')
        x = x.replace('\n', '')

        row_count += 1 
        x = x.strip()
        a_line = x.split('\t')
        if len(a_line) != 8:
            continue

        try:    
            date = a_line[0].strip()
            time = a_line[1].strip()
            action = a_line[2].strip()
            user = a_line[3].strip()
            module = a_line[4].strip()
            fname = a_line[5].strip()
            rule = a_line[6].strip()
            final = a_line[7].strip()
            
            found = a_line[6].strip()
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue    

        try:        
            ins_string = 'insert into mfeaplogs values(NULL,'
            ins_string += S_QUOTE + hostname + S_QUOTE + COMMA
            ins_string += S_QUOTE + date + S_QUOTE + COMMA
            ins_string += S_QUOTE + time + S_QUOTE + COMMA
            ins_string += S_QUOTE + action + S_QUOTE + COMMA
            ins_string += S_QUOTE + user + S_QUOTE + COMMA
            ins_string += S_QUOTE + module + S_QUOTE + COMMA
            ins_string += S_QUOTE + fname + S_QUOTE + COMMA
            ins_string += S_QUOTE + rule + S_QUOTE + COMMA
            ins_string += S_QUOTE + final + S_QUOTE + ')'
            
            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count +=1
            continue
    
    con.commit()
    cur.close()
    a_file.close()
    
    print '+++', row_count, 'total rows processed.'
    print '+++', err_count, 'parse errors.'
    print '---', ins_count, 'database insertion errors.'     

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
    global g_strMFEAPLogFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import McAfee Access Protection scan log files into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('mfeap_file_or_dir', help = 'MFE AP log file or directory of MFE AP log files.')
    
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
    g_strMFEAPLogFileorDir = os.path.join(results.mfeap_file_or_dir,"logs","av")

    return 0

if __name__ == "__main__":
    main()

