"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-02-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        netstat2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-12-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-01-21 16:13:48 -0800 (Sat, 21 Jan 2012) $
$Revision: 1333 $
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
 *  netstat2db.py
 *  This script loads netstat -ano output into a database for analysis.
 *  It was created using Python 2.7.
 *  The only external python module required is MySQL-Python (http://mysql-python.sourceforge.net/)
  *==========================================================================*/
"""
import sqlite3
import os
import subprocess
import argparse
import logging # Log levels: DEBUG INFO WARNING ERROR CRITICAL
import re

"""
Function List
==========================================
main():                                    Script entry point
CreatNetstatFileList(Netstat_file_or_dir): Creates a list of Netstat files to process
VerifyTsklistFileOrDir(full_path):         Verifies Netstat file or directory exist
OpenOrCreateDB(db_name, user, pwd):        Opens or creates a database
OpenSQLiteDB(db_path):                     Opens or creates an SQLite3 database
IsNetstatFile(path):                       Verifies a file is a Netstat output file
LoadTsklistFiles(Netstat_file, con):       Loads a Netstat file into a database
GetCommandLineArgs():                      Processes command line parms
"""

"""
Netstat Fields
=================
Proto
Local Address
Foreign Address
State
PID
"""

# Database schemas
sqlite_netstat_table_schema = """
Create Table netstat (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Hostname TEXT NOT NULL,
Proto TEXT NOT NULL,
Local_Address TEXT,
Foreign_Address TEXT,
State TEXT,
PID INT,
Executable_Info TEXT);
"""
mysql_netstat_table_schema = """
Create Table netstat (ID INT NOT NULL AUTO_INCREMENT,
Hostname TEXT NOT NULL,
Proto TEXT NOT NULL,
Local_Address TEXT,
Foreign_Address TEXT,
State TEXT,
PID INT,
Executable_Info TEXT,
PRIMARY KEY (ID));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strNetstatFileorDir = ''
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
                        filename=os.path.join(g_logPath,'netstat2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'netstat2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'netstat2db_insert_errors.txt'), 'w')
    
    # Verify passed in Netstat file or dir exists
    if VerifyNetstatFileOrDir(g_strNetstatFileorDir) != 0:
        logging.error('--- File or directory ' + g_strNetstatFileorDir + 'does not exist.') 
        print 'File or directory ', g_strNetstatFileorDir, 'does not exist.'
        return -1

    # Open or create the Netstat database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of Netstat logs to process
    lstNetstatFileList = CreateNetstatFileList(g_strNetstatFileorDir)
    logging.debug('+++ CreateNetstatFileList(' + g_strNetstatFileorDir + ')')
    if len(lstNetstatFileList) == 0:
         logging.error('--- No Netstat files were found to process.')
         print 'No Netstat files were found.'
         return -1
    if len(lstNetstatFileList) == 1: 
        print '+++ There is', str(len(lstNetstatFileList)), 'Netstat files to process...'
    if len(lstNetstatFileList) > 1: 
        print '+++ There are', str(len(lstNetstatFileList)), 'Netstat files to process...'

    for afile in lstNetstatFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadEvents(' + g_strNetstatFileorDir + '\\' + afile + ')')
            print '+++ Loading Netstat file', afile, 'into SQLite3 database...'
            LoadNetstatFiles(afile, g_conSQLite)

    logging.info('+++ Closing database.')
    print '+++ Loading of Netstat files completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of Netstat files to process
string Netstat_file_or_dir - path to Netstat or directory of Netstat files

Returns:
list of Netstat filenames, -1 if fatal error
"""
def CreateNetstatFileList(Netstat_file_or_dir):

    logging.debug('+++ CreateNetstatFileList(' + Netstat_file_or_dir + ')')
        
    # Sanity checks
    if len(Netstat_file_or_dir) == 0:
        logging.error('CreateNetstatFileList(Netstat_file_or_dir) - Netstat_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(Netstat_file_or_dir) == False:
        logging.error('CreateNetstatFileList(Netstat_file_or_dir) - Netstat_file_or_dir param path does not exist.')
        return -1
    
    lstNetstatFiles = []

    # Verify a single Netstat log file
    if os.path.isfile(Netstat_file_or_dir):
        res = IsNetstatFile(Netstat_file_or_dir)
        if res != -1 and res != False:
            lstNetstatFiles.append(Netstat_file_or_dir)
        else:
            logging.info('--- ' + Netstat_file_or_dir + 'is not a Netstat file.')
            print '--- ', Netstat_file_or_dir, ' is not a Netstat file.'
        return lstNetstatFiles

    # Verify a dir of Netstat output files
    dir_list = os.listdir(Netstat_file_or_dir)
    for afile in dir_list:
        res = IsNetstatFile(Netstat_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstNetstatFiles.append(Netstat_file_or_dir + '\\' + afile)
        else:
            print '---', Netstat_file_or_dir + '\\' + afile, 'is not an Netstat output file.'
    
    return lstNetstatFiles


"""
Verify Netstat file or directory
Parameters:
string full_path - path to Netstat file or directory of Netstat files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyNetstatFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_netstat_table_schema)
            return 0
        except:
            logging.error('--- Error creating netstat table in SQLite3 database.')
            print '--- Error creating netstat table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the Netstat table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS netstat')
            g_conSQLite.execute(sqlite_netstat_table_schema)
            return 0
        except:
            logging.error('--- Error dropping netstat table from SQLite3 database.')
            print '--- Error dropping netstat table from SQLite3 database.'
            return -1

    # Make sure Netstat table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM netstat;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating netstat table in SQLite3 database.')
        g_conSQLite.execute(sqlite_netstat_table_schema)
        
    return 0


"""
Verifies a file is a Netstat output file
Returns:
    -1 if there was an error
    False if file is not a Netstat output file
"""
def IsNetstatFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid Netstat file
    # We look for the field row within the first 10 lines of the file
    Netstat_file = None
    try:
        Netstat_file = file(path, 'r')
        for x in range(10):
            sig = Netstat_file.readline()
            if sig.find('Proto') >= 0 and sig.find('Local Address') >= 0 and sig.find('Foreign Address') >= 0 \
            and sig.find('State') >= 0:
                Netstat_file.close()
                return True
    except:
        Netstat_file.close()
        return -1

    Netstat_file.close()
    return False

"""
Helper function for LoadNetstatFiles that checks whether a row
of data is already in the row data array.
"""
def isIn(r,rows):
    for row in rows:
        # protocol
        if r[0] != row[0]:
            continue
        # local address
        if r[1] != row[1]:
            continue
        # foreign address
        if r[2] != row[2]:
            continue
        # state
        if r[3] != row[3]:
            continue
        return True
    return False

"""
Load Netstat output into Netstat table
Parameters:
string Netstat_file     - Netstat file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadNetstatFiles(Netstat_file, con):

    # Sanity checks
    if len(Netstat_file) == 0:
        logging.error('--- LoadNetstatFiles() - Netstat_file parameter is empty.')
        return -1
    if os.path.exists(Netstat_file) == False:
        logging.error('--- LoadNetstatFiles() - Netstat_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadNetstatFiles() - con parameter is not valid.')
        return -1
    
    # Open the Netstat file
    a_file = file(Netstat_file, 'r')
    if a_file == None:
        logging.error('--- LoadNetstatFiles() - error opening Netstat_file ' + Netstat_file + '.')
        return -1

    hostname = os.path.basename(Netstat_file)
    if hostname.find('_') > 0:
        hostname = hostname.split('_')[0]
    
    cur = con.cursor()
    row_count = 0
    err_count = 0
    ins_count = 0

    exp = re.compile(r' *')

    rows = []
    lastrow = None
    executableInfo = ""
    newentry = False
    for x in a_file:
        # Strip ', " , \n
        x = x.replace("'", '')
        x = x.replace('\n', '')

        # Ignore empty rows
        if len(x) == 0:
            continue
       
        ## Ignore header rows
        if x.find('Active Connections') >=0 or \
           x.find('Proto') >= 0 or \
           x.find('Local Address') >= 0:
            continue
        
        a_row = x.strip()
        if a_row.startswith("TCP") or a_row.startswith("UDP"):
            if lastrow != None and not isIn(lastrow, rows):
                rows.append((lastrow[0],lastrow[1],lastrow[2],lastrow[3],
                             lastrow[4],executableInfo[:-1]))
                newentry = False
                lastrow = None
                executableInfo = ""
                
            a_row = exp.split(a_row)

            ## Ignore the junk
            if a_row[2].find('0.0.0.0:0') >= 0 or \
               a_row[2].find('127.0.0.1') >=0 or \
               a_row[2].find('[::]:0') >=0 or \
               a_row[2].find('*:*') >=0:
                continue

            row_count += 1
            newentry = True
            
            ## Populate the Netstat table
            try:
                proto = a_row[0]
                local_addr = a_row[1]
                for_addr = a_row[2]
                state = a_row[3]
                if len(a_row) > 4:
                    pid = a_row[4]
                else:
                    pid = -1
                lastrow = proto,local_addr,for_addr,state,pid
            except:
                g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
                err_count += 1
                continue
        elif newentry:
            executableInfo += a_row + ","

    for row in rows:
        try:
            ins_string = 'insert into netstat values(NULL,'
            ins_string += S_QUOTE + hostname + S_QUOTE + COMMA
            ins_string += S_QUOTE + row[0] + S_QUOTE + COMMA
            ins_string += S_QUOTE + row[1] + S_QUOTE + COMMA
            ins_string += S_QUOTE + row[2] + S_QUOTE + COMMA
            ins_string += S_QUOTE + row[3] + S_QUOTE + COMMA
            ins_string += str(row[4]) + COMMA
            ins_string += S_QUOTE + row[5] + S_QUOTE +')'

            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count += 1
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
    global g_strNetstatFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import Netstat -ano output into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('Netstat_file_or_dir', help = 'Netstat output file or directory of Netstat output files.')
    
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
    g_strNetstatFileorDir = os.path.join(results.Netstat_file_or_dir,"network","netstat")

    return 0

if __name__ == "__main__":
    main()

