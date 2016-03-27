"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-02-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        md5deep2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     12-28-2011
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-02-01 06:20:49 -0800 (Wed, 01 Feb 2012) $
$Revision: 1360 $
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
 *  md5deep2db.py
 *  This script loads md5deep output into a database for analysis.
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
main():                                     Script entry point
CreateHashFileList(hash_file_or_dir):       Creates a list of hash files to process
VerifyHashFileOrDir(full_path):             Verifies hash file or directory exist
OpenOrCreateDB(db_name, user, pwd):         Opens or creates a database
OpenSQLiteDB(db_path):                      Opens or creates an SQLite3 database
IsHashFile(path):                           Verifies a file is a md5deep file
LoadHashes(hash_file, con):                 Loads a hash file into a database
GetCommandLineArgs():                       Processes command line parms
"""

# Database schemas
sqlite_hash_table_schema = """
Create Table hashes (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Hostname TEXT NOT NULL,
MD5 TEXT NOT NULL,
Filename TEXT NOT NULL)
"""

mysql_hash_table_schema = """
Create Table hashes (ID INT NOT NULL AUTO_INCREMENT,
Hostname TEXT NOT NULL,
MD5 TEXT NOT NULL,
Filename TEXT NOT NULL,
PRIMARY KEY (ID));
"""

sqlite_uniq_hash_table_schema = """
Create Table uniq_hashes (ID INTEGER PRIMARY KEY AUTOINCREMENT,
MD5 TEXT NOT NULL UNIQUE)
"""

mysql_uniq_hash_table_schema = """
Create Table uniq_hashes (ID INT NOT NULL AUTO_INCREMENT,
MD5 CHAR(32) NOT NULL,
PRIMARY KEY (ID),
UNIQUE(MD5));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strHashFileorDir = ''
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
                        filename=os.path.join(g_logPath,'md5deep2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'md5deep2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'md5deep2db_insert_errors.txt'), 'w')
    
    # Verify passed in hash file or dir exists
    if VerifyHashFileOrDir(g_strHashFileorDir) != 0:
        logging.error('--- File or directory ' + g_strHashFileorDir + 'does not exist.') 
        print 'File or directory ', g_strHashFileorDir, 'does not exist.'
        return -1

    # Open or create the hash database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of hash logs to process
    lstHashFileList = CreateHashFileList(g_strHashFileorDir)
    logging.debug('+++ CreateHashFileList(' + g_strHashFileorDir + ')')
    if len(lstHashFileList) == 0:
         logging.error('--- No hash files were found to process.')
         print 'No hash files were found.'
         return -1
    if len(lstHashFileList) == 1: 
        print '+++ There is', str(len(lstHashFileList)), 'hash files to process...'
    if len(lstHashFileList) > 1: 
        print '+++ There are', str(len(lstHashFileList)), 'hash files to process...'

    for afile in lstHashFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadHashes(' + g_strHashFileorDir + '\\' + afile + ')')
            print '+++ Loading hash file', afile, 'into SQLite3 database...'
            LoadHashes(afile, g_conSQLite)

    logging.info('+++ Closing database.')
    print '+++ Loading of hash files completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()

    return 0

"""
Create a list of hash files to process
string hash_file_or_dir - path to hash or directory of hash files

Returns:
list of hash filenames, -1 if fatal error
"""
def CreateHashFileList(hash_file_or_dir):

    logging.debug('+++ CreateHashFileList(' + hash_file_or_dir + ')')
        
    # Sanity checks
    if len(hash_file_or_dir) == 0:
        logging.error('CreateHashFileList(hash_file_or_dir) - hash_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(hash_file_or_dir) == False:
        logging.error('CreateHashFileList(hash_file_or_dir) - hash_file_or_dir param path does not exist.')
        return -1
    
    lstHashFiles = []

    # Verify a single hash file
    if os.path.isfile(hash_file_or_dir):
        res = IsHashFile(hash_file_or_dir)
        if res != -1 and res != False:
            lstHashFiles.append(hash_file_or_dir)
        else:
            logging.info('--- ' + hash_file_or_dir + 'is not a hash file.')
            print '--- ', hash_file_or_dir, ' is not a hash file.'
        return lstHashFiles

    # Verify a dir of md5deep files output files
    dir_list = os.listdir(hash_file_or_dir)
    for afile in dir_list:
        res = IsHashFile(hash_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstHashFiles.append(hash_file_or_dir + '\\' + afile)
        else:
            print '---', hash_file_or_dir + '\\' + afile, 'is not a hash file.'
    
    return lstHashFiles


"""
Verify hash file or directory
Parameters:
string full_path - path to hash file or directory of hash files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyHashFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_hash_table_schema)
            g_conSQLite.execute(sqlite_uniq_hash_table_schema)
            return 0
        except:
            logging.error('--- Error creating hash table in SQLite3 database.')
            print '--- Error creating hash table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the hash table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS hashes')
            g_conSQLite.execute('DROP TABLE IF EXISTS uniq_hashes')
            g_conSQLite.execute(sqlite_hash_table_schema)
            g_conSQLite.execute(sqlite_uniq_hash_table_schema)
            return 0
        except:
            logging.error('--- Error dropping hashes table from SQLite3 database.')
            print '--- Error dropping hashes table from SQLite3 database.'
            return -1

    # Make sure hashes table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM hashes LIMIT 5;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating hashes table in SQLite3 database.')
        g_conSQLite.execute(sqlite_hash_table_schema)
        g_conSQLite.execute(sqlite_uniq_hash_table_schema)

    return 0


"""
Verifies a file is a md5deep hash file
Returns:
    -1 if there was an error
    False if file is not aH ashMyFiles file
"""
def IsHashFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid hash file
    hash_file = None
    try:
        hash_file = file(path, 'r')
        # Read the first 10 lines and make sure it has a space at col 32
        for x in range(10):    
            sig = hash_file.readline()
            if sig.find(' ') != 32:
                hash_file.close()
                return -1
        return True
    except:
        hash_file.close()
        return -1
        
    hash_file.close()
    return False

"""
Load hashes into hashes table
Parameters:
string hash_file          - Hash file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadHashes(hash_file, con):

    # Sanity checks
    if len(hash_file) == 0:
        logging.error('--- LoadHashes() - hash_file parameter is empty.')
        return -1
    if os.path.exists(hash_file) == False:
        logging.error('--- LoadHashes() - hash_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadHashes() - con parameter is not valid.')
        return -1
    
    # Open the hash file
    h_file = file(hash_file, 'r')
    if h_file == None:
        logging.error('--- LoadHashes() - error opening hash_file ' + hash_file + '.')
        return -1

    host = os.path.basename(hash_file)
    if host.find('_') > 0:
        host = host.split('_')[0]
    
    cur = con.cursor()
    row_count = 0
    err_count = 0
    ins_count = 0

    for x in h_file:
        # Strip ', " , \n, and \t
        x = x.replace("'", '')
        x = x.replace('"', '')
        x = x.replace('\n', '')

        a_row = x.split('  ')
       
        row_count += 1
        ## Populate the hashes table
        try:
            MD5 = a_row[0].strip()
            Full_Path = a_row[1].strip()
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
        
        try:
            ins_string = 'insert into hashes values(NULL,'
            ins_string += S_QUOTE + host + S_QUOTE + COMMA
            ins_string += S_QUOTE + MD5 + S_QUOTE + COMMA
            ins_string += S_QUOTE + Full_Path + S_QUOTE + ')'

            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count += 1
            continue

        ## Populate the uniq_hashes table
        try:
            ins_string = 'insert into uniq_hashes values(NULL,'
            ins_string += S_QUOTE + MD5 + S_QUOTE + ')'
            cur.execute(ins_string)
        except:
            pass    # There will be exceptions due to non-unique hash inserts - ignore them
            continue

    con.commit()
    cur.close()
    h_file.close()
    
    print '+++', row_count, 'total hashes processed.'
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
    global g_strHashFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import hash files into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('hash_file_or_dir', help = 'hash file or directory of hash files.')
    
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
    g_strHashFileorDir = os.path.join(results.hash_file_or_dir,"hashes")

    return 0


if __name__ == "__main__":
    main()

"""
md5deep field names
=======================
MD5            
Filename       
"""
