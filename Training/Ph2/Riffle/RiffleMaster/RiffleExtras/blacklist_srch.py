"""
/////////////////////////////////////////////////////////////////////////////
// Name:        blacklist_srch.py
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
 *  blacklist_srch.py
 *  This script reads bad url from the Shane Shook list and determines
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
IsBlacklistFile(path):                       Verifies a file is a Shook bad file list
OpenRiffleDB(db_name, user, pwd):            Opens a Ripple database
OpenSQLiteDB(db_path):                       Opens NSRL SQLite3 database
OpenMySQLDB(db_name, user, pwd):             Opens NSRL MySQL database
GetCommandLineArgs():                        Processes command line parms
BlacklistSearch()                            Read the blacklist file and determine url matches
"""

# Command line arg variables
#g_strDBName = ''
g_strDBName = ''

g_bSQLiteDB = True
g_bMySQLDB = False
g_strUserName = ''
g_strUserPwd  = ''
g_strBlacklistFile = ''
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
    logging.basicConfig(format='%(asctime)s %(message)s', filename='blacklist_srch_log.txt', filemode='w', level=g_LogLevel)

    # Get command line args
    logging.debug('+++ Getting command line args.')
    if GetCommandLineArgs() != 0:
        return -1

    # Verify passed in badfile.txt file exists
    if os.path.exists(g_strBlacklistFile) != True:
        logging.error('--- Shook blacklist file ' + g_strBlacklistFile + 'does not exist.') 
        print 'Shook bad file ', g_strBlacklistFile, 'does not exist.'
        return -1

    # Open the Riffle database
    print '+++ Opening database', g_strDBName, '...'
    if OpenDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Perform the searches
    BlacklistSearch()

    logging.info('+++ Closing database.')
    print '+++ Searching of Shook blacklist file completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    return 0

"""
Searches for blacklist URL's in the Riffle database. Any URL that is found
is output to stdout or an output file

Parameters:
None

Returns:
0 if success, -1 if error
"""
def BlacklistSearch():
    global g_strBlacklistFile
    global g_strOutfile

    bad_file = None
    out_file = None
    url_count = 0
    hit_count = 0
    percent_found = 0

    if os.path.exists(g_strBlacklistFile) == False:
        print '--- Shook blacklist file ',  g_strBlacklistFile, ' does not exist.'
        return -1

    try:
        bad_file = file(g_strBlacklistFile, 'r')
    except:
        print '--- Unable to open Shook blacklist file',  g_strBlacklistFile, '.'
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

    # Read Shook blacklist file and look up URL in Riffle database
    sql = ''
    if out_file:
        out_file.write('Address\tType\tUtility\tHostname\tRecordName\tTime_To_Live\tData_Length\tSection\tPTRRecord\tARecord\n')
    for x in bad_file:
        x = x.replace('\n', '')
        shook_row = x.split('\t')
        if len(shook_row) == 1:
            shook_row[1] = ''
            shook_row[2] = ''
        url_count += 1
        sql = "SELECT * from dnscache where record_name like '" + shook_row[0] + "'"
        try:
            cur.execute(sql)
            while(1):
                outrow = ''
                res = cur.fetchone()
                if res == None:
                    break
                hit_count += 1
                outrow = shook_row[0] + TAB + shook_row[1] + TAB + shook_row[1] + TAB + res[1] + TAB + res[2] + TAB + res[3] + TAB + str(res[4]) + TAB + str(res[5]) + TAB + res[7] + res[8] +'\n'
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

    print "Total URL's searched: ", url_count
    print "Url's found in Riffle database: ", hit_count

    return 0

"""
Open a Riffle database
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
        g_conSQLite.execute("SELECT * FROM dnscache LIMIT 5;")
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
            if 'dnscache' in x:
                hash_tbl_exists = True
    except:
        logging.error('--- Error connecting to Riffle MySQL database.')
        print '--- Error connecting to Riffle MySQL database.'
        cur.close()
        return -1

    if hash_tbl_exists == False:
        logging.error('--- dnscache table does not exist in MySQL database.')
        print '--- dnscache table does not exist in MySQL database.'
        cur.close()
        return -1

    return 0

"""
Verifies a file is Shook blacklist file
Returns:
    -1 if there was an error
    True if file is a blacklist file
    False if file is not a blacklist file
"""
def IsBlacklistFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid Shook file
    Blacklist_File = None
    try:
        Blacklist_File = file(path, 'r')
        arow = Bad_File.readline()
        if arow.lower().find('address') >= 0 and arow.lower().find('type') >= 0 and arow.lower().find('utility') >= 0:
            return True
    except:
        Blacklist_File.close()
        return -1

    Blacklist_File.close()    
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
    global g_strBlacklistFile
    global g_strOutfile

    parser = argparse.ArgumentParser(description='Search for blacklisted URLs in Riffle database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-m', dest='mysql_db', action='store_true', help = 'use MySQL database engine.')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-o', dest='out_file', default = '', help = 'output file name.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('blacklist_file', help = 'File of Shook blacklisted URLs.')
    
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
    g_strBlacklistFile = results.blacklist_file
    g_strOutfile = results.out_file
    
    return 0


if __name__ == "__main__":
    main()

