"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-02-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        autorunsc2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-12-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-01-21 16:07:03 -0800 (Sat, 21 Jan 2012) $
$Revision: 1323 $
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
 *  autorunsc2db.py
 *  This script loads SysInternal's autorunsc output into a database for analysis.
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
main():                                          Script entry point
CreateAutorunscFileList(autorunsc_file_or_dir):  Creates a list of autorunsc files to process
VerifyAutorunscFileOrDir(full_path):             Verifies autorunsc file or directory exist
OpenOrCreateDB(db_name, user, pwd):              Opens or creates a database
OpenSQLiteDB(db_path):                           Opens or creates an SQLite3 database
IsAutorunscFile(path):                           Verifies a file is a autorunsc output file
LoadAutorunscFiles(autorunsc_file, con):         Loads a autorunsc file into a database
GetCommandLineArgs():                            Processes command line parms
"""

"""
Autorunsc Fields
=================
Entry Location
Entry
Enabled
Category
Description
Publisher
Image Path
Launch String
MD5
SHA-1
SHA-256
"""

# Database schemas
sqlite_autorunsc_table_schema = """
Create Table autorunsc (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Hostname TEXT NOT NULL,
Entry_Location TEXT NOT NULL,
Entry TEXT NOT NULL,
Enabled TEXT,
Category TEXT,
Description TEXT  NOT NULL,
Publisher TEXT  NOT NULL,
Image_Path TEXT  NOT NULL,  
Launch_String TEXT,
MD5 TEXT,
SHA1 TEXT,
SHA256 TEXT);
"""

mysql_autorunsc_table_schema = """
Create Table autorunsc (ID INT NOT NULL AUTO_INCREMENT,
Hostname TEXT NOT NULL,
Entry_Location TEXT NOT NULL,
Entry TEXT NOT NULL,
Enabled TEXT,
Category TEXT,
Description TEXT  NOT NULL,
Publisher TEXT  NOT NULL,
Image_Path TEXT  NOT NULL,  
Launch_String TEXT,
MD5 TEXT,
SHA1 TEXT,
SHA256 TEXT,
PRIMARY KEY (ID));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strAutorunscFileorDir = ''
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
                        filename=os.path.join(g_logPath,'autorunsc2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'autorunsc2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'autorunsc2b_insert_errors.txt'), 'w')
    
    # Verify passed in autorunsc file or dir exists
    if VerifyAutorunscFileOrDir(g_strAutorunscFileorDir) != 0:
        logging.error('--- File or directory ' + g_strAutorunscFileorDir + 'does not exist.') 
        print 'File or directory ', g_strAutorunscFileorDir, 'does not exist.'
        return -1

    # Open or create the autorunsc database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of autorunsc logs to process
    lstAutorunscFileList = CreateAutorunscFileList(g_strAutorunscFileorDir)
    logging.debug('+++ CreateAutorunscFileList(' + g_strAutorunscFileorDir + ')')
    if len(lstAutorunscFileList) == 0:
         logging.error('--- No autorunsc files were found to process.')
         print 'No autorunsc files were found.'
         return -1
    if len(lstAutorunscFileList) == 1: 
        print '+++ There is', str(len(lstAutorunscFileList)), 'autorunsc files to process...'
    if len(lstAutorunscFileList) > 1: 
        print '+++ There are', str(len(lstAutorunscFileList)), 'autorunsc files to process...'

    for afile in lstAutorunscFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadEvents(' + g_strAutorunscFileorDir + '\\' + afile + ')')
            print '+++ Loading autorunsc file', afile, 'into SQLite3 database...'
            LoadAutorunscFiles(afile, g_conSQLite)

    logging.info('+++ Closing database.')
    print '+++ Loading of autorunsc files completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of autorunsc files to process
string autorunsc_file_or_dir - path to autorunsc or directory of autorunsc files

Returns:
list of autorunsc filenames, -1 if fatal error
"""
def CreateAutorunscFileList(autorunsc_file_or_dir):

    logging.debug('+++ CreateAutorunscFileList(' + autorunsc_file_or_dir + ')')
        
    # Sanity checks
    if len(autorunsc_file_or_dir) == 0:
        logging.error('CreateAutorunscFileList(autorunsc_file_or_dir) - autorunsc_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(autorunsc_file_or_dir) == False:
        logging.error('CreateAutorunscFileList(autorunsc_file_or_dir) - autorunsc_file_or_dir param path does not exist.')
        return -1
    
    lstAutorunscFiles = []

    # Verify a single autorunsc log file
    if os.path.isfile(autorunsc_file_or_dir):
        res = IsAutorunscFile(autorunsc_file_or_dir)
        if res != -1 and res != False:
            lstAutorunscFiles.append(autorunsc_file_or_dir)
        else:
            logging.info('--- ' + autorunsc_file_or_dir + 'is not an autorunsc file.')
            print '--- ', autorunsc_file_or_dir, ' is not an autorunsc file.'
        return lstAutorunscFiles

    # Verify a dir of autorunsc output files
    dir_list = os.listdir(autorunsc_file_or_dir)
    for afile in dir_list:
        res = IsAutorunscFile(autorunsc_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstAutorunscFiles.append(autorunsc_file_or_dir + '\\' + afile)
        else:
            print '---', autorunsc_file_or_dir + '\\' + afile, 'is not an autorunsc output file.'
    
    return lstAutorunscFiles

"""
Verify autorunsc file or directory
Parameters:
string full_path - path to autorunsc file or directory of autorunsc files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyAutorunscFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_autorunsc_table_schema)
            return 0
        except:
            logging.error('--- Error creating autorunsc table in SQLite3 database.')
            print '--- Error creating autorunsc table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the autorunsc table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS autorunsc')
            g_conSQLite.execute(sqlite_autorunsc_table_schema)
            return 0
        except:
            logging.error('--- Error dropping autorunsc table from SQLite3 database.')
            print '--- Error dropping autorunsc table from SQLite3 database.'
            return -1

    # Make sure autorunsc table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM autorunsc;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating autorunsc table in SQLite3 database.')
        g_conSQLite.execute(sqlite_autorunsc_table_schema)
        
    return 0

"""
Verifies a file is an autorunsc output file
Returns:
    -1 if there was an error
    False if file is not an autorunsc file
"""
def IsAutorunscFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid autorunsc file
    autorunsc_file = None
    try:
        autorunsc_file = file(path, 'r')
        sig = autorunsc_file.readline()
        if sig.find('Entry Location') >= 0 and sig.find('Entry') >= 0 and sig.find('Enabled') >= 0 and sig.find('Category') >= 0 \
        and sig.find('Description') >= 0 and sig.find('Publisher') >= 0 and sig.find('Image') >= 0 \
        and sig.find('Path') >= 0 and sig.find('Launch String') >= 0 and sig.find('MD5') >= 0 \
        and sig.find('SHA-1') >= 0 and sig.find('SHA-256'):
            autorunsc_file.close()
            return True
    except:
        autorunsc_file.close()
        return -1

    autorunsc_file.close()    
    return False

"""
Load autorunc output into autorunsc table
Parameters:
string autorunsc_file    - autorunsc file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadAutorunscFiles(autorunsc_file, con):
    global g_ParseErrors
    global g_InsertErrors
    
    # Sanity checks
    if len(autorunsc_file) == 0:
        logging.error('--- LoadAutorunsc() - autorunsc_file parameter is empty.')
        return -1
    if os.path.exists(autorunsc_file) == False:
        logging.error('--- LoadAutorunsc() - autorunsc_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadAutorunsc() - con parameter is not valid.')
        return -1
    
    # Open the autorunsc file
    a_file = file(autorunsc_file, 'r')
    if a_file == None:
        logging.error('--- LoadAutorunsc() - error opening autorunsc_file ' + autorunsc_file + '.')
        return -1
 
    hostname = os.path.basename(autorunsc_file)
    if hostname.find('_') > 0:
        hostname = hostname.split('_')[0]
    
    cur = con.cursor()
    row_count = 0
    ins_count = 0
    err_count = 0
    idx1 = 0
    idx2 = 0

    for x in a_file:
 
        x = x.replace('\n', '')

        if len(x) == 0:
            continue
                
        ## Ignore header row if it exists
        if 'Entry' in x and 'Enabled' in x:
            continue

        if x.find('"') < 0:
            continue
        
        row_count += 1
        a_row = x

        ## Populate the autorunsc table
        try:
            idx1 = 1
            idx2 = a_row.find('",', 2)
            entry_loc = a_row[idx1:idx1+idx2-1]
            idx1 = idx2 + 3
            idx2 = a_row.find('",', idx1+1)
            entry = a_row[idx1:idx2]
            idx1 = idx2 + 2
            idx2 = a_row.find(',', idx1+1)
            enabled = a_row[idx1:idx2]
            idx1 = idx2 + 2
            idx2 = a_row.find('",', idx1+1)
            category = a_row[idx1:idx2]
            idx1 = idx2 + 3
            idx2 = a_row.find('",', idx1+2)
            description = a_row[idx1:idx2]
            description = description.replace("'", "")
            description = description.replace(",", " ")
            description = description.replace('"',"")
            idx1 = idx2 + 3
            idx2 = a_row.find('",', idx1+1)
            publisher = a_row[idx1:idx2]
            publisher = publisher.replace("'", "")
            publisher = publisher.replace(",", " ")
            publisher = publisher.replace('"',"")
            idx1 = idx2 + 3
            idx2 = a_row.find('",', idx1+1)
            image_path = a_row[idx1:idx2]
            image_path = a_row[idx1:idx2]
            image_path = image_path.replace("'", "")
            image_path = image_path.replace(',',",")
            image_path = image_path.replace('"',"")
            idx1 = idx2 + 3
            idx2 = a_row.find('",', idx1+1)
            launch_str = a_row[idx1:idx2]
            launch_str = launch_str.replace("'", "")
            launch_str = launch_str.replace(','," ")
            launch_str = launch_str.replace('"',"")
            idx1 = idx2 + 2
            idx2 = a_row.find(',', idx1+2)
            MD5 = a_row[idx1:idx2]
            if len(MD5) != 32:
                continue
            idx1 = idx2 + 2
            idx2 = a_row.find(',', idx1+1)
            SHA1 = a_row[idx1:idx2]
            idx1 = idx2 + 2
            idx2 = a_row.find(',', idx1+1)
            SHA256 = a_row[idx1:idx2]
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
       
        try:
            ins_string = 'insert into autorunsc values(NULL,'
            ins_string += S_QUOTE + hostname + S_QUOTE + COMMA
            ins_string += S_QUOTE + entry_loc + S_QUOTE + COMMA
            ins_string += S_QUOTE + entry + S_QUOTE + COMMA
            ins_string += S_QUOTE + enabled + S_QUOTE + COMMA
            ins_string += S_QUOTE + category + S_QUOTE + COMMA
            ins_string += S_QUOTE + description + S_QUOTE + COMMA
            ins_string += S_QUOTE + publisher + S_QUOTE + COMMA
            ins_string += S_QUOTE + image_path + S_QUOTE + COMMA
            ins_string += S_QUOTE + launch_str + S_QUOTE + COMMA
            ins_string += S_QUOTE + MD5 + S_QUOTE + COMMA
            ins_string += S_QUOTE + SHA1 + S_QUOTE +  COMMA
            ins_string += S_QUOTE + SHA256 + S_QUOTE + ')'

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
    global g_strAutorunscFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import autorunsc output into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('autorunsc_file_or_dir', help = 'autorunsc output file or directory of autorunsc output files.')
    
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
    g_strAutorunscFileorDir = os.path.join(results.autorunsc_file_or_dir,"autoruns")

    return 0


if __name__ == "__main__":
    main()

