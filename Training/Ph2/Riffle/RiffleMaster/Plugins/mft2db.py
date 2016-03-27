"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-02-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        mft2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     12-28-2011
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-01-21 16:13:27 -0800 (Sat, 21 Jan 2012) $
$Revision: 1332 $
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
 *  mft2db.py
 *  This script loads MFTDump output into a database for analysis.
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
MFTDump field names
=======================
RecNo
Deleted
Directory
ADS
Filename
siCreateTime (UTC)
siModTime (UTC)
siMFTModTime (UTC)
siAccessTime (UTC)
ActualSize
AllocSize
Ext
FullPath
fnCreateTime (UTC)
fnModTime (UTC)
fnMFTModTime (UTC)
fnAccessTime (UTC)
ReadOnly
Hidden
System
Hostname
"""

"""
Function List
==========================================
main():                                   Script entry point
CreateMFTFileList(mft_file_or_dir):       Creates a list of MFT files to process
VerifyMFTFileOrDir(full_path):            Verifies MFT file or directory exist
OpenOrCreateDB(db_name, user, pwd):       Opens or creates a database
OpenSQLiteDB(db_path):                    Opens or creates an SQLite3 database
IsMFTFile(path):                          Verifies a file is a MFT file
LoadMFTes(mft_file, con):                 Loads a MFT file into a database
GetCommandLineArgs():                     Processes command line parms
"""

# Database schemas
sqlite_mft_table_schema = """
Create Table mft (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Hostname TEXT NOT NULL,
RecNo INTEGER,
Deleted INTEGER,
Directory INTEGER,
ADS INTEGER,
Filename TEXT NOT NULL,
siCreateTimeZ TEXT,
siModTimeZ TEXT,
siMFTModTimeZ TEXT,
siAccessTimeZ TEXT,
ActualSize INTEGER,
AllocSize INTEGER,
Ext TEXT,
FullPath  TEXT,
fnCreateTimeZ TEXT,
fnModTimeZ  TEXT,
fnMFTModTimeZ TEXT,
fnAccessTimeZ TEXT,
ReadOnly INTEGER,
Hidden INTEGER,
System INTEGER)
"""

mysql_mft_table_schema = """
Create Table mft (ID INT NOT NULL AUTO_INCREMENT,
Hostname TEXT NOT NULL,
RecNo INTEGER,
Deleted INTEGER,
Directory INTEGER,
ADS INTEGER,
Filename TEXT NOT NULL,
siCreateTimeZ TEXT,
siModTimeZ TEXT,
siMFTModTimeZ TEXT,
siAccessTimeZ TEXT,
ActualSize INTEGER,
AllocSize INTEGER,
Ext TEXT,
FullPath  TEXT,
fnCreateTimeZ TEXT,
fnModTimeZ  TEXT,
fnMFTModTimeZ TEXT,
fnAccessTimeZ TEXT,
ReadOnly INTEGER,
Hidden INTEGER,
System INTEGER,
PRIMARY KEY (ID));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strMFTFileorDir = ''
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
                        filename=os.path.join(g_logPath,'mft2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'mft2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'mft2db_insert_errors.txt'), 'w')
    
    # Verify passed in MFT file or dir exists
    if VerifyMFTFileOrDir(g_strMFTFileorDir) != 0:
        logging.error('--- File or directory ' + g_strMFTFileorDir + 'does not exist.') 
        print 'File or directory ', g_strMFTFileorDir, 'does not exist.'
        return -1

    # Open or create the mft database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of MFT logs to process
    lstMFTFileList = CreateMFTFileList(g_strMFTFileorDir)
    logging.debug('+++ CreateMFTFileList(' + g_strMFTFileorDir + ')')
    if len(lstMFTFileList) == 0:
         logging.error('--- No MFT files were found to process.')
         print 'No MFT files were found.'
         return -1
    if len(lstMFTFileList) == 1: 
        print '+++ There is', str(len(lstMFTFileList)), 'MFT files to process...'
    if len(lstMFTFileList) > 1: 
        print '+++ There are', str(len(lstMFTFileList)), 'MFT files to process...'

    for afile in lstMFTFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadMFT(' + g_strMFTFileorDir + '\\' + afile + ')')
            print '+++ Loading MFT file', afile, 'into SQLite3 database...'
            LoadMFT(afile, g_conSQLite)

    logging.info('+++ Closing database.')
    print '+++ Loading of MFT files completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()

    return 0

"""
Create a list of MFT files to process
string mft_file_or_dir - path to MFT or directory of MFT files

Returns:
list of mft filenames, -1 if fatal error
"""
def CreateMFTFileList(mft_file_or_dir):

    logging.debug('+++ CreateMFTFileList(' + mft_file_or_dir + ')')
        
    # Sanity checks
    if len(mft_file_or_dir) == 0:
        logging.error('CreateMFTFileList(mft_file_or_dir) - mft_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(mft_file_or_dir) == False:
        logging.error('CreateMFTFileList(mft_file_or_dir) - mft_file_or_dir param path does not exist.')
        return -1
    
    lstMFTFiles = []

    # Verify a single mft file
    if os.path.isfile(mft_file_or_dir):
        res = IsMFTFile(mft_file_or_dir)
        if res != -1 and res != False:
            lstMFTFiles.append(mft_file_or_dir)
        else:
            logging.erro('--- ' + mft_file_or_dir + 'is not a mft file.')
            print '--- ', mft_file_or_dir, ' is not a mft file.'
        return lstMFTFiles

    # Verify a dir of MFTDump output files
    dir_list = os.listdir(mft_file_or_dir)
    for afile in dir_list:
        res = IsMFTFile(mft_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstMFTFiles.append(mft_file_or_dir + '\\' + afile)
        else:
            print '---', mft_file_or_dir + '\\' + afile, 'is not a MFT file.'
    
    return lstMFTFiles

"""
Verify MFT file or directory
Parameters:
string full_path - path to MFT file or directory of MFT files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyMFTFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_mft_table_schema)
            return 0
        except:
            logging.error('--- Error creating mft table in SQLite3 database.')
            print '--- Error creating mft table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the mft table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS mft')
            g_conSQLite.execute(sqlite_mft_table_schema)
            return 0
        except:
            logging.error('--- Error dropping mft table from SQLite3 database.')
            print '--- Error dropping mft from SQLite3 database.'
            return -1

    # Make sure mft table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM mft;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating mft table in SQLite3 database.')
        g_conSQLite.execute(sqlite_mft_table_schema)

    return 0

"""
Verifies a file is a MFTDump file
Returns:
    -1 if there was an error
    False if file is not a MFTDump file
"""
def IsMFTFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid MFT file
    mft_file = None
    try:
        mft_file = file(path, 'r')
        sig = mft_file.readline()
        if sig.find('RecNo') >= 0 and sig.find('Deleted') >= 0 and sig.find('Directory') >= 0 and sig.find('ADS') >= 0:
            mft_file.close()
            return True
    except:
        mft_file.close()
        return -1

    mft_file.close()
    return False

"""
Load MFT into mft table
Parameters:
string mft_file          - MFT file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadMFT(mft_file, con):

    # Sanity checks
    if len(mft_file) == 0:
        logging.error('--- LoadMFT() - mft_file parameter is empty.')
        return -1
    if os.path.exists(mft_file) == False:
        logging.error('--- LoadMFT() - mft_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadMFT() - con parameter is not valid.')
        return -1
    
    # Open the MFT file
    a_file = file(mft_file, 'r')
    if a_file == None:
        logging.error('--- LoadMFT() - error opening mft_file ' + mft_file + '.')
        return -1

    row_count = 0
    ins_count = 0
    err_count = 0
    host = os.path.basename(mft_file)
    if host.find('.') > 0:
        host = host.split('_')[0]
    
    cur = con.cursor()

    for x in a_file:
        
        # Strip ', " , \n, and \t
        x = x.replace("'", '')
        #x = x.replace('(', '\(')
        #x = x.replace(')', '\)')
        x = x.replace('\n', '')

        a_row = x.split('\t')
        ## Ignore header row if it exists
        if 'RecNo' in a_row and 'Deleted' in a_row:
            continue
        
        row_count += 1
        
        ## Populate the mft table
        try:
            recno = a_row[0]
            deleted = a_row[1]
            dir = a_row[2]
            ads = a_row[3]
            filename = a_row[4]
            si_create = a_row[5]
            si_mod = a_row[6]
            si_mftmod = a_row[7]
            si_access = a_row[8]
            actual_size = a_row[9]
            if len(actual_size) == 0:
                actual_size = '0'
            alloc_size = a_row[10]
            if len(alloc_size) == 0:
                alloc_size = '0'
            ext = a_row[11]
            full_path = a_row[12]
            fn_create = a_row[13]
            fn_mod = a_row[14]
            fn_mftmod = a_row[15]
            fn_access = a_row[16]
            ro = a_row[17]
            hidden = a_row[18]
            sys = a_row[19]
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue

        try:
            ins_string = 'insert into mft values(NULL,'
            ins_string += S_QUOTE + host + S_QUOTE + COMMA
            ins_string += recno + COMMA
            ins_string += deleted + COMMA
            ins_string += dir + COMMA
            ins_string += ads + COMMA        
            ins_string += S_QUOTE + filename + S_QUOTE + COMMA
            ins_string += S_QUOTE + si_create + S_QUOTE + COMMA
            ins_string += S_QUOTE + si_mod + S_QUOTE + COMMA
            ins_string += S_QUOTE + si_mftmod + S_QUOTE + COMMA
            ins_string += S_QUOTE + si_access + S_QUOTE + COMMA
            ins_string += actual_size + COMMA
            ins_string += alloc_size + COMMA
            ins_string += S_QUOTE + ext + S_QUOTE + COMMA
            ins_string += S_QUOTE + full_path + S_QUOTE + COMMA
            ins_string += S_QUOTE + fn_create + S_QUOTE + COMMA
            ins_string += S_QUOTE + fn_mod + S_QUOTE + COMMA
            ins_string += S_QUOTE + fn_mftmod + S_QUOTE + COMMA
            ins_string += S_QUOTE + fn_access + S_QUOTE + COMMA
            ins_string += ro + COMMA
            ins_string += hidden + COMMA
            ins_string += sys + ')'

            cur.execute(ins_string)
        except:
            g_InsertErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
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
    global g_strMFTFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import MFT files into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('mft_file_or_dir', help = 'mft file or directory of mft files.')
    
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
    g_strMFTFileorDir = os.path.join(results.mft_file_or_dir,"mft","mftdumped")

    return 0


if __name__ == "__main__":
    main()
