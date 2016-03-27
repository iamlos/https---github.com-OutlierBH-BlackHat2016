"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-02-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        schtasks2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-12-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-02-01 05:52:47 -0800 (Wed, 01 Feb 2012) $
$Revision: 1357 $
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
 *  schtasks2db.py
 *  This script loads schtask logs into a database for analysis.
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
main():                                         Script entry point
CreateSchTaskFileList(g_strSchTaskFileorDir):   Creates a list of SchTasks files to process
VerifySchTaskFileOrDir(full_path):              Verifies SchTask log file or directory exist
OpenOrCreateDB(db_name, user, pwd):             Opens or creates a database
OpenSQLiteDB(db_path):                          Opens or creates an SQLite3 database
IsSchTaskFile(path):                            Verifies a file is a McAfee OAS log file
LoadSchTaskFiles(g_strSchTaskFileorDir, con):   Loads a SchTask log into a database
GetCommandLineArgs():                           Processes command line parms
"""

"""
SchTask log Fields
=================
Folder
TaskName
NextRunTime
Status
"""

# Database schemas
sqlite_schtasks_table_schema = """
Create Table schtasks (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Hostname TEXT NOT NULL,
Folder TEXT,
TaskName TEXT,
NextRun TEXT,
Status TEXT);
"""

mysql_schtasks_table_schema = """
Create Table schtasks (ID INT NOT NULL AUTO_INCREMENT,
Hostname TEXT NOT NULL,
Folder TEXT,
TaskName TEXT,
NextRun TEXT,
Status TEXT,
PRIMARY KEY (ID));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strSchTaskFileorDir = ''
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
                        filename=os.path.join(g_logPath,'schtasks2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'schtasks2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'schtasks2db_insert_errors.txt'), 'w')
    
    # Verify passed in SchTask file or dir exists
    if VerifySchTaskFileOrDir(g_strSchTaskFileorDir) != 0:
        logging.error('--- File or directory ' + g_strSchTaskFileorDir + 'does not exist.') 
        print 'File or directory ', g_strSchTaskFileorDir, 'does not exist.'
        return -1

    # Open or create the database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of SchTask logs to process
    lstSchTaskLogFileList = CreateSchTaskFileList(g_strSchTaskFileorDir)
    logging.debug('+++ CreateOASFileList(' + g_strSchTaskFileorDir + ')')
    if len(lstSchTaskLogFileList) == 0:
         logging.error('--- No SchTask log files were found to process.')
         print 'No SchTask log files were found.'
         return -1
    if len(lstSchTaskLogFileList) == 1: 
        print '+++ There is', str(len(lstSchTaskLogFileList)), 'SchTask log files to process...'
    if len(lstSchTaskLogFileList) > 1: 
        print '+++ There are', str(len(lstSchTaskLogFileList)), 'SchTask log files to process...'

    for afile in lstSchTaskLogFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadEvents(' + g_strSchTaskFileorDir + '\\' + afile + ')')
            print '+++ Loading SchTask log file', afile, 'into SQLite3 database...'
            LoadSchTaskFiles(afile, g_conSQLite)

    logging.info('+++ Closing database.')
    print '+++ Loading of SchTask log files completed...'

    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of SchTask log files to process
string schtasklog_file_or_dir - path to SchTask log file or directory of SchTask log files

Returns:
list of SchTask log filenames, -1 if fatal error
"""
def CreateSchTaskFileList(schtasklog_file_or_dir):

    logging.debug('+++ CreateOASFileList(' + schtasklog_file_or_dir + ')')
        
    # Sanity checks
    if len(schtasklog_file_or_dir) == 0:
        logging.error('CreateSchTaskFileList(schtasklog_file_or_dir) - schtasklog_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(schtasklog_file_or_dir) == False:
        logging.error('CreateSchTaskFileList(schtasklog_file_or_dir) - schtasklog_file_or_dir param path does not exist.')
        return -1
    
    lstSchTaskLogFiles = []

    # Verify a single SchTask log file
    if os.path.isfile(schtasklog_file_or_dir):
        res = IsSchTaskFile(schtasklog_file_or_dir)
        if res != -1 and res != False:
            lstSchTaskLogFiles.append(schtasklog_file_or_dir)
        else:
            logging.info('--- ' + schtasklog_file_or_dir + 'is not a SchTask log file.')
            print '--- ', schtasklog_file_or_dir, ' is not a SchTask log file.'
        return lstSchTaskLogFiles

    # Verify a dir of SchTask log files
    dir_list = os.listdir(schtasklog_file_or_dir)
    for afile in dir_list:
        res = IsSchTaskFile(schtasklog_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstSchTaskLogFiles.append(schtasklog_file_or_dir + '\\' + afile)
        else:
            print '---', schtasklog_file_or_dir + '\\' + afile, 'is not an SchTask log file.'
    
    return lstSchTaskLogFiles


"""
Verify SchTask log file or directory
Parameters:
string full_path - path to SchTask log file or directory of SchTask log files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifySchTaskFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_schtasks_table_schema)
            return 0
        except:
            logging.error('--- Error creating schtasks table in SQLite3 database.')
            print '--- Error creating schtasks table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the SchTask table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS schtasks')
            g_conSQLite.execute(sqlite_schtasks_table_schema)
            return 0
        except:
            logging.error('--- Error dropping schtasks table from SQLite3 database.')
            print '--- Error dropping schtasks table from SQLite3 database.'
            return -1

    # Make sure schtasks table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM schtasks LIMIT 5;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating schtasks table in SQLite3 database.')
        g_conSQLite.execute(sqlite_schtasks_table_schema)
        
    return 0


"""
Verifies a file is a SchTask log file
Returns:
    -1 if there was an error
    False if file is not a SchTask log file
"""
def IsSchTaskFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid SchTask log file
    # No structure to log file. We look for the fields we know must be in the log
    schtasklog_file = None

    try:
        schtasklog_file = file(path, 'r')
        for x in range(15):
            sig = schtasklog_file.readline()
            if len(sig) and sig.find('Folder:') >= 0:
                sig = schtasklog_file.readline()
                if len(sig) and sig.find('TaskName') >= 0:
                    sig = schtasklog_file.readline()
                    if len(sig) and sig.find('======') >= 0:
                        schtasklog_file.close()
                        return True
    except:
        schtasklog_file.close()
        return -1

    schtasklog_file.close()
    return False

"""
Load SchTask log fileinto schtasks table
Parameters:
string schtask_file      - SchTask log file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadSchTaskFiles(schtask_file, con):
    global g_ParseErrors
    global g_InsertErrors
    row_count = 0

    # Sanity checks
    if len(schtask_file) == 0:
        logging.error('--- LoadSchTaskFiles() - schtask_file parameter is empty.')
        return -1
    if os.path.exists(schtask_file) == False:
        logging.error('--- LoadSchTaskFiles() - schtask_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadSchTaskFiles() - con parameter is not valid.')
        return -1
    
    # Open the SchTask log file
    a_file = file(schtask_file, 'r')
    if a_file == None:
        logging.error('--- LoadSchTaskFiles() - error opening schtask_file ' + schtask_file + '.')
        return -1

    hostname = os.path.basename(schtask_file)
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
        if 'folder:' in x.lower():
            folder = x[x.find(':')+1:]
            folder.strip()
            continue;
        if 'taskname' in x.lower():
            continue;
        if '=========' in x.lower():
            continue;
        if 'info:' in x.lower():
            folder = ''
            continue;
        
        row_count += 1 
        
        try:    
            task    = x[:40].strip()
            nextrun = x[40:64].strip()
            status  = x[64:80].strip()
           
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue    

        try:        
            ins_string = 'insert into schtasks values(NULL,'
            ins_string += S_QUOTE + hostname + S_QUOTE + COMMA
            ins_string += S_QUOTE + folder + S_QUOTE + COMMA
            ins_string += S_QUOTE + task + S_QUOTE + COMMA
            ins_string += S_QUOTE + nextrun + S_QUOTE + COMMA
            ins_string += S_QUOTE + status + S_QUOTE + ')'
            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count +=1
            continue
    
    con.commit()
    cur.close()
    a_file.close()
    
    print '+++', row_count, 'total rows processed.'
    print '---', err_count, 'parse errors.'
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
    global g_strSchTaskFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import McAfee On Access scan log file into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('schtask_file_or_dir', help = 'SchTask log file or directory of SchTask log files.')
    
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
    g_strSchTaskFileorDir = os.path.join(results.schtask_file_or_dir,"scheduler")

    return 0

if __name__ == "__main__":
    main()

