"""
/////////////////////////////////////////////////////////////////////////////
// Name:        blacklist2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-19-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-01-18 20:20:41 -0800 (Wed, 18 Jan 2012) $
$Revision: 1297 $
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
 *  blacklist2db.py
 *  This script loads Shane Shooks blacklist into a database for analysis.
 *  It was created using Python 2.7.
 *  The only external python module required is MySQL-Python (http://mysql-python.sourceforge.net/)
  *==========================================================================*/
"""
import sqlite3
import MySQLdb
import os
import subprocess
import argparse
import logging # Log levels: DEBUG INFO WARNING ERROR CRITICAL 

"""
Function List
==========================================
main():                                          Script entry point
CreateBlacklistFileList(blacklist_file_or_dir):  Creates a list of blacklist files to process
VerifyBlacklistFileOrDir(full_path):             Verifies blacklist file or directory exist
OpenOrCreateDB(db_name, user, pwd):              Opens or creates a database
OpenSQLiteDB(db_path):                           Opens or creates an SQLite3 database
OpenMySQLDB(db_name, user, pwd):                 Opens or creates a MySQL database
IsBlacklistFile(path):                           Verifies a file is a Blacklist file
LoadBlacklistFiles(hash_file, con):              Loads blacklist file into a database
GetCommandLineArgs():                            Processes command line parms
"""

"""
Blacklist Fields
=================
Address
Type
Description
"""

# Database schemas
sqlite_blacklist_table_schema = """
Create Table blacklist (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Address TEXT NOT NULL,
Type TEXT NOT NULL,
Description TEXT NOT NULL);
"""

mysql_blacklist_table_schema = """
Create Table blacklist (ID INT NOT NULL AUTO_INCREMENT,
Address TEXT NOT NULL,
Type TEXT NOT NULL,
Description TEXT NOT NULL,
PRIMARY KEY (ID));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_bMySQLDB = False
g_strUserName = ''
g_strUserPwd = ''
g_strBlacklistFileorDir = ''

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

    # Set log levels
    logging.basicConfig(format='%(asctime)s %(message)s', filename='blacklist2db_log.txt', filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file('blacklist2db_log.txt', 'w')
    g_InsertErrors = file('blacklist2db_log.txt', 'w')
    
    # Get command line args
    logging.debug('+++ Getting command line args.')
    if GetCommandLineArgs() != 0:
        return -1

    # Verify passed in blacklist file or dir exists
    if VerifyBlacklistFileOrDir(g_strBlacklistFileorDir) != 0:
        logging.error('--- File or directory ' + g_strBlacklistFileorDir + 'does not exist.') 
        print 'File or directory ', g_strBlacklistFileorDir, 'does not exist.'
        return -1

    # Open or create the blacklist database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of blacklist's to process
    lstBlacklistFileList = CreateBlacklistFileList(g_strBlacklistFileorDir)
    logging.debug('+++ CreateBlacklistFileList(' + g_strBlacklistFileorDir + ')')
    if len(lstBlacklistFileList) == 0:
         logging.error('--- No blacklist files were found to process.')
         print 'No blacklist files were found.'
         return -1
    if len(lstBlacklistFileList) == 1: 
        print '+++ There is', str(len(lstBlacklistFileList)), 'blacklist files to process...'
    if len(lstBlacklistFileList) > 1: 
        print '+++ There are', str(len(lstBlacklistFileList)), 'blacklist files to process...'

    for afile in lstBlacklistFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadBlacklistFiles(' + g_strBlacklistFileorDir + '\\' + afile + ')')
            print '+++ Loading blacklist file', afile, 'into SQLite3 database...'
            LoadBlacklistFiles(afile, g_conSQLite)

        if g_bMySQLDB == True:
            logging.debug('MySQL LoadBlacklistFiles(' + g_strBlacklistFileorDir + '\\' + afile + ')')
            print '+++ Loading blacklist file', afile, 'into MySQL database...'
            LoadBlacklistFiles(afile, g_conMySQL)
            
    logging.info('+++ Closing database.')
    print '+++ Loading of blacklist files completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of blacklist files to process
string blacklist_file_or_dir - path to blacklist or directory of blacklist files

Returns:
list of blacklist filenames, -1 if fatal error
"""
def CreateBlacklistFileList(blacklist_file_or_dir):

    logging.debug('+++ CreateBlacklistFileList(' + blacklist_file_or_dir + ')')
        
    # Sanity checks
    if len(blacklist_file_or_dir) == 0:
        logging.error('CreateBlacklistFileList(blacklist_file_or_dir) - blacklist_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(blacklist_file_or_dir) == False:
        logging.error('CreateBlacklistFileList(blacklist_file_or_dir) - blacklist_file_or_dir param path does not exist.')
        return -1
    
    lstBlacklistFiles = []

    # Verify a single blacklist log file
    if os.path.isfile(blacklist_file_or_dir):
        res = IsBlacklistFile(blacklist_file_or_dir)
        if res != -1 and res != False:
            lstBlacklistFiles.append(blacklist_file_or_dir)
        else:
            logging.info('--- ' + blacklist_file_or_dir + 'is not a blacklist file.')
            print '--- ', blacklist_file_or_dir, ' is not a blacklist file.'

        return lstBlacklistFiles

    # Verify a dir of blacklist files
    dir_list = os.listdir(blacklist_file_or_dir)
    for afile in dir_list:
        res = IsBlacklistFile(blacklist_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstBlacklistFiles.append(blacklist_file_or_dir + '\\' + afile)
        else:
            print '---', blacklist_file_or_dir + '\\' + afile, 'is not a blacklist file.'
    
    return lstBlacklistFiles


"""
Verify blacklist file or directory
Parameters:
string full_path - path to blacklist file or directory of blacklist files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyBlacklistFileOrDir(full_path):
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

    if g_bMySQLDB == True:
        if len(user)== 0 or len(pwd) == 0:
            logging.error('--- OpenOrCreateDB(db_name, user, pwd): - you must provide user and pwd parameters for MySQL databases.')
            print '--- You must provide user and pwd parameters for MySQL databases.'    
        if OpenMySQLDB(db_name, user, pwd) == 0:
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
            g_conSQLite.execute(sqlite_blacklist_table_schema)
            return 0
        except:
            logging.error('--- Error creating blacklist table in SQLite3 database.')
            print '--- Error creating blacklist table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the blacklist table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS blacklist')
            g_conSQLite.execute(sqlite_blacklist_table_schema)
            return 0
        except:
            logging.error('--- Error dropping blacklist table from SQLite3 database.')
            print '--- Error dropping blacklist table from SQLite3 database.'
            return -1

    # Make sure blacklist table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM blacklist;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating blacklist table in SQLite3 database.')
        g_conSQLite.execute(sqlite_blacklist_table_schema)
        
    return 0

"""
Open/create a MySQL database.
Parameters:
string db_path - name of MySQL database
string user    - user name
string pwd     - user passwd

Returns:
0 if successfully opened or created, -1 if error
"""
def OpenMySQLDB(db_name, user, pwd):
    global g_conMySQL

    # Sanity checks
    if len(db_name) == 0:
        logging.error('--- OpenMySQLDB(db_name, user, pwd) - db_name parameter is not valid.')
        return -1

    if len(user) == 0:
        logging.error('--- OpenMySQLDB(db_name, user, pwd) - user parameter is not valid.')
        return -1

    if len(pwd) == 0:
        logging.error('--- OpenMySQLDB(db_name, user, pwd) - pwd parameter is not valid.')
        return -1

    # Connect to MySQL instance
    try:
        g_conMySQL = MySQLdb.connect(user=user, passwd=pwd)
    except:
        logging.error('--- Unable to connect to MySQL instance.')
        print '--- Unable to connect to MySQL instance.'
        g_conMySQL = None
        return -1

    # Determine if database exists
    db_name = os.path.basename(g_strDBName)
    db_exists = False
    cur = None
    try:
        cur = g_conMySQL.cursor()
        cur.execute("SHOW databases;")
        db_tuples = cur.fetchall()
        for x in db_tuples:
            if db_name in x:
                db_exists = True
    except:
        logging.error('--- Exception occurred when querying MySQL instance.')
        print '--- Exception occurred when querying MySQL instance.'
        g_conMySQL = None
        return -1
    
    if g_bCreateDB == False and db_exists == False:
        logging.error('--- MySQL database does not exist and create flag is false.')
        print '--- MySQL database does not exist and create flag is false.'
        return -1

    if db_exists == False:
        try:
            cur.execute('CREATE database ' + db_name + ';')
            cur.execute('USE ' + db_name + ';')
            cur.execute(mysql_blacklist_table_schema)
            return 0
        except:
            logging.error('--- Error creating blacklist table in MySQL database')
            print '--- Error creating blacklist table in MySQL database'
            g_conMySQL = None
            return -1

    # Empty the blacklist table if requested
    if g_bEmptyDB == True:
        try:
            cur.execute('USE ' + db_name + ';')
            cur.execute('DROP TABLE if exists blacklist;')
            cur.execute(mysql_blacklist_table_schema)
            return 0
        except:
            logging.error('--- Error dropping blacklist table from MySQL database.')
            print '--- Error dropping blacklist table from MySQL database.'
            g_conSQLite = None
            return -1

    # Make sure blacklist table exists
    try:
        cur.execute('USE ' + db_name + ';')
        tbl_exists = False
        cur.execute("SHOW tables;")
        db_tuples = cur.fetchall()
        for x in db_tuples:
            if 'blacklist' in x:
                tbl_exists = True
        if tbl_exists == False:
            cur.execute(mysql_blacklist_table_schema)
            return 0
    except:
        logging.error('--- Error dropping blacklist table from MySQL database.')
        print '--- Error dropping blacklist table from MySQL database.'
        g_conSQLite = None
        return -1
   
    return 0

"""
Verifies a file is an blacklist output file
Returns:
    -1 if there was an error
    False if file is not an blacklist file
"""
def IsBlacklistFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid blacklist file
    blacklist_file = None
    try:
        blacklist_file = file(path, 'r')
        sig = blacklist_file.readline()
        sig = sig.lower()
        if sig.find('address') >= 0 and sig.find('type') >= 0 and sig.find('description') >= 0:
            blacklist_file.close()
            return True
    except:
        blacklist_file.close()
        return -1

    blacklist_file.close()    
    return False

"""
Load blacklist file into blacklist table
Parameters:
string blacklist_file    - blacklist file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadBlacklistFiles(blacklist_file, con):
    global g_ParseErrors
    global g_InsertErrors
    
    # Sanity checks
    if len(blacklist_file) == 0:
        logging.error('--- LoadBlacklistFiles() - blacklist_file parameter is empty.')
        return -1
    if os.path.exists(blacklist_file) == False:
        logging.error('--- LoadBlacklistFiles() - blacklist_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadBlacklistFiles() - con parameter is not valid.')
        return -1
    
    # Open the blacklist file
    a_file = file(blacklist_file, 'r')
    if a_file == None:
        logging.error('--- LoadBlacklistFiles() - error opening blacklist_file ' + blacklist_file + '.')
        return -1

    cur = con.cursor()
    row_count = 0
    ins_count = 0
    err_count = 0

    for x in a_file:
 
        x = x.replace('\n', '')

        if len(x) == 0:
            continue
                
        ## Ignore header row if it exists
        hdr = x.lower()
        if 'address' in hdr and 'type' in hdr and 'description' in hdr:
            continue
        
        row_count += 1
        a_row = x.split('\t')

        ## Populate the blacklist table
        try:
            add = a_row[0]
            type = a_row[1]
            desc = a_row[2]
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
       
        try:
            ins_string = 'insert into blacklist values(NULL,'
            ins_string += S_QUOTE + add + S_QUOTE + COMMA
            ins_string += S_QUOTE + type + S_QUOTE + COMMA
            ins_string += S_QUOTE + desc + S_QUOTE + ')'

            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count += 1
            continue

    con.commit()
    cur.close()
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
    global g_bMySQLDB
    global g_strUserName
    global g_strUserPwd
    global g_strBlacklistFileorDir

    parser = argparse.ArgumentParser(description='Import blacklist into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-m', dest='mysql_db', action='store_true', help = 'use MySQL database engine.')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('blacklist_file_or_dir', help = 'blacklist output file or directory of blacklist files.')
    
    try:
        results = parser.parse_args()
    except IOError, msg:
        return -1

    # Command line sanity check
    if results.mysql_db == True:
        results.sqlite_db = False
        if results.user_name == None or results.user_pwd == None:
            logging.error('--- You must provide a user name and password for MySQL databases.')
            print '--- You must provide a user name and password for MySQL databases.'
            return -1

    # Make sure only one database type is selected
    if results.sqlite_db == True and results.mysql_db == True:
        logging.error('--- You can only select one database type (-m OR -l).')
        print '--- You can only select one database type (-m OR -l).'
        return -1
       
    g_strDBName = results.db_name
    g_bCreateDB = results.create_db
    g_bEmptyDB = results.empty_db
    g_bSQLiteDB = results.sqlite_db
    g_bMySQLDB = results.mysql_db
    g_strUserName = results.user_name
    g_strUserPwd = results.user_pwd
    g_strBlacklistFileorDir = results.blacklist_file_or_dir

    return 0


if __name__ == "__main__":
    main()

