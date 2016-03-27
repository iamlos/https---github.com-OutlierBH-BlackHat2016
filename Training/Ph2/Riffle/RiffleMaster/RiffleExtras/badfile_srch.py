"""
/////////////////////////////////////////////////////////////////////////////
// Name:        badfile_srch.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     02-29-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-02-01 04:52:47 -0800 (Wed, 01 Feb 2012) $
$Revision: 1346 $
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
 *  badfile_srch.py
 *  This script reads bad file names from the Shane Shook list and determines
 *  if they are in a Riffle databse. If a file is located in the Riffle MFT
 *  table - it is printed to stdout out or an output file.
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
main():                                      Script entry point
IsBadFileList(path):                         Verifies a file is a Shook bad file list
OpenRiffleDB(db_name, user, pwd):            Opens a Ripple database
OpenSQLiteDB(db_path):                       Opens NSRL SQLite3 database
OpenMySQLDB(db_name, user, pwd):             Opens NSRL MySQL database
GetCommandLineArgs():                        Processes command line parms
FileSearch()                                 Read the badfile file and determine file matches
"""

# Command line arg variables
#g_strDBName = ''
g_strDBName = ''

g_bSQLiteDB = True
g_bMySQLDB = False
g_strUserName = ''
g_strUserPwd  = ''
g_strBadfile = ''
g_strOutfile = ''

# Other globals
S_QUOTE = '\''
TAB = '\t'
COMMA = ','
g_conSQLite    = None
g_conMySQL     = None
g_LogLevel     = logging.INFO


def main():

    # Set log levels
    logging.basicConfig(format='%(asctime)s %(message)s', filename='badfile_srch_log.txt', filemode='w', level=g_LogLevel)

    # Get command line args
    logging.debug('+++ Getting command line args.')
    if GetCommandLineArgs() != 0:
        return -1

    # Verify passed in badfile.txt file exists
    if os.path.exists(g_strBadfile) != True:
        logging.error('--- Shook bad file ' + g_strBadfile + 'does not exist.') 
        print 'Shook bad file ', g_strBadfile, 'does not exist.'
        return -1

    # Open the Riffle database
    print '+++ Opening database', g_strDBName, '...'
    if OpenDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Perform the searches
    print '+++ Performing search. This may take a while...'
    FileSearch()

    logging.info('+++ Closing database.')
    print '+++ Searching of Shook bad file list completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    return 0

"""
Searches for bad files in the Riffle database. Any file that is not found
is output to stdout or an output file

Parameters:
None

Returns:
0 if success, -1 if error
"""
def FileSearch():
    global g_strBadfile
    global g_strOutfile

    bad_file = None
    out_file = None
    file_count = 0
    hit_count = 0
    percent_found = 0

    if os.path.exists(g_strBadfile) == False:
        print '--- Shook bad file ',  g_strBadfile, ' does not exist.'
        return -1

    try:
        bad_file = file(g_strBadfile, 'r')
    except:
        print '--- Unable to open Shook bad file',  g_strBadfile, '.'
        return -1
        
    if len(g_strOutfile):
        try:
            out_file = file(g_strOutfile, 'w')
        except:
            print '--- Unable to open output file',  g_strOutfile, '.'
            return -1


    # Get connection to the database
    if g_bSQLiteDB == True and g_conSQLite != None:
        cur = g_conSQLite.cursor()

    if g_bMySQLDB == True and g_conMySQL != None:
        cur = g_conMySQL.cursor()

    # Read Shook bad file and look up file in Riffle database
    sql = ''
    if out_file:
        out_file.write('Threat\tShookFile\tHostname\tFilename\tFullPath\tAllocSize\tsiCreateTimeZ\tsiModTimeZ\tsiAccessTimeZ\tfnCreateTimeZ\tfnModTimeZ\tfnAccessTimeZ\n')
    for x in bad_file:
        x = x.replace('\n', '')
        shook_row = x.split('\t')
        if len(shook_row) == 1:
            shook_row[1] = ''
        file_count += 1
        sql = "SELECT Hostname, Filename, FullPath, AllocSize, siCreateTimeZ, siModTimeZ, siAccessTimeZ, fnCreateTimeZ, fnModTimeZ, fnAccessTimeZ from mft where fullpath like '" + shook_row[0] + "'"
        try:
            cur.execute(sql)
            while(1):
                outrow = ''
                res = cur.fetchone()
                if res == None:
                    break
                hit_count += 1
                outrow = shook_row[1] + TAB + shook_row[0] + TAB + res[0] + TAB + res[1] + TAB + res[2] + TAB + str(res[3]) + TAB + res[4] + TAB + res[5] + TAB + res[6] + TAB + res[7] + TAB + res[8] + TAB + res[9] + '\n'
                if out_file:
                    out_file.write(outrow)
                else:
                    print outrow
        except:
            continue
    cur.close()
    bad_file.close()
    if out_file:
        out_file.close()

    print 'Total files searched: ', file_count
    print 'Files found in Riffle database: ', hit_count

    
    return 0

"""
Open an Riffle database
Parameters:
string db_name - name of the database
string user    - user name of db if required
string pwd     - user pwd of db if required

Returns:
0 if database if opened, -1 if error
"""
def OpenDB(db_name, user, pwd):
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
Open Riffle SQLite3 database.
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
    
    if os.path.exists(db_path) == False:
        logging.error('--- OpenSQLiteDB(db_path) - db_path does not exist.')
        print '--- OpenSQLiteDB(db_path) - db_path does not exist.'
        return -1

    # Make sure Riffle mft table exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
        g_conSQLite.execute("SELECT * FROM mft LIMIT 5;")
    except sqlite3.OperationalError, err:
        logging.error('--- Error opening Riffle SQLite3 mft table.')
        print '--- Error opening Riffle SQLite3 mft table.'
        return -1
        
    return 0

"""
Open MySQL database.
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

    # Make sure Riffle tables exists
    hash_tbl_exists = False
    try:
        cur.execute('USE ' + db_name + ';')
        cur.execute("SHOW tables;")
        db_tuples = cur.fetchall()
        for x in db_tuples:
            if 'mft' in x:
                hash_tbl_exists = True
    except:
        logging.error('--- Error connecting to Riffle MySQL database.')
        print '--- Error connecting to Riffle MySQL database.'
        cur.close()
        return -1

    if hash_tbl_exists == False:
        logging.error('--- mft table does not exist in MySQL database.')
        print '--- mft table does not exist in MySQL database.'
        cur.close()
        return -1

    return 0

"""
Verifies a file is Shook badfile file
Returns:
    -1 if there was an error
    True if file is a hash file
    False if file is not a hash file
"""
def IsBadFileList(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid Shook file
    Bad_File = None
    try:
        Bad_File = file(path, 'r')
        for x in range(25):
            if Bad_File.readline().find('%\\') == 0:
                return True
    except:
        Bad_File.close()
        return -1

    Bad_File.close()    
    return False

"""
Process command line args
Parameters: None
Returns: 0 if success, -1 if invalid command line args
"""
def GetCommandLineArgs():

    global g_strDBName
    global g_bSQLiteDB
    global g_bMySQLDB
    global g_strUserName
    global g_strUserPwd
    global g_strBadfile
    global g_strOutfile

    parser = argparse.ArgumentParser(description='Search for suspect files in a Riffle database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-m', dest='mysql_db', action='store_true', help = 'use MySQL database engine.')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-o', dest='out_file', default = '', help = 'output file name.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('bad_file_list', help = 'File of suspect filenames.')
    
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
    g_bSQLiteDB = results.sqlite_db
    g_bMySQLDB = results.mysql_db
    g_strUserName = results.user_name
    g_strUserPwd = results.user_pwd
    g_strBadfile = results.bad_file_list
    g_strOutfile = results.out_file
    
    return 0


if __name__ == "__main__":
    main()

