"""
/////////////////////////////////////////////////////////////////////////////
//
// Update: 04-02-2013
// Update Author: Chuck Hall
//
/////////////////////////////////////////////////////////////////////////////
// Name:        dnscache2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-12-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-01-21 16:06:19 -0800 (Sat, 21 Jan 2012) $
$Revision: 1322 $
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
 *  dnscache2db.py
 *  This script loads ipconfig /dispaydns output into a database for analysis.
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
CreateDnscacheFileList(Dnscache_file_or_dir):  Creates a list of Dnscache files to process
VerifyDnscacheFileOrDir(full_path):            Verifies Dnscache file or directory exist
OpenOrCreateDB(db_name, user, pwd):            Opens or creates a database
OpenSQLiteDB(db_path):                         Opens or creates an SQLite3 database
IsDnscacheFile(path):                          Verifies a file is a Dnscache output file
LoadDnscacheFiles(Dnscache_file, con):         Loads a Dnscache file into a database
GetCommandLineArgs():                          Processes command line parms
"""

"""
Dnscache Fields
=================
Record Name
Record Type
Time To Live
Data Length
Section
A (Host) Record
PTR Record
"""

# Database schemas
sqlite_dnscache_table_schema = """
Create Table dnscache (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Hostname TEXT NOT NULL,
Record_Name TEXT NOT NULL,
Record_Type TEXT,
Time_To_Live INTEGER,
Data_Length INTEGER,
Section TEXT,
PTR_Record TEXT,
A_Record TEXT);
"""
mysql_dnscache_table_schema = """
Create Table dnscache (ID INT NOT NULL AUTO_INCREMENT,
Hostname TEXT NOT NULL,
Record_Name TEXT NOT NULL,
Record_Type TEXT,
Time_To_Live INTEGER,
Data_Length INTEGER,
Section TEXT,
PTR_Record TEXT,
A_Record TEXT,
PRIMARY KEY (ID));
"""

# Command line arg variables
g_strDBName = ''
g_bCreateDB = False
g_bEmptyDB = False
g_bSQLiteDB = True
g_strUserName = ''
g_strUserPwd = ''
g_strDnscacheFileorDir = ''
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
                        filename=os.path.join(g_logPath,'dnscache2db_log.txt'), \
                        filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file(os.path.join(g_logPath,'dnscache2db_parse_errors.txt'), 'w')
    g_InsertErrors = file(os.path.join(g_logPath,'dnscache2db_insert_errors.txt'), 'w')
    
    # Verify passed in Dnscache file or dir exists
    if VerifyDnscacheFileOrDir(g_strDnscacheFileorDir) != 0:
        logging.error('--- File or directory ' + g_strDnscacheFileorDir + 'does not exist.') 
        print 'File or directory ', g_strDnscacheFileorDir, 'does not exist.'
        return -1

    # Open or create the Dnscache database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of Dnscache logs to process
    lstDnscacheFileList = CreateDnscacheFileList(g_strDnscacheFileorDir)
    logging.debug('+++ CreateDnscacheFileList(' + g_strDnscacheFileorDir + ')')
    if len(lstDnscacheFileList) == 0:
         logging.error('--- No Dnscache files were found to process.')
         print 'No Dnscache files were found.'
         return -1
    if len(lstDnscacheFileList) == 1: 
        print '+++ There is', str(len(lstDnscacheFileList)), 'Dnscache files to process...'
    if len(lstDnscacheFileList) > 1: 
        print '+++ There are', str(len(lstDnscacheFileList)), 'Dnscache files to process...'

    for afile in lstDnscacheFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadEvents(' + g_strDnscacheFileorDir + '\\' + afile + ')')
            print '+++ Loading Dnscache file', afile, 'into SQLite3 database...'
            LoadDnscacheFiles(afile, g_conSQLite)

    logging.info('+++ Closing database.')
    print '+++ Loading of Dnscache files completed...'

    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of Dnscache files to process
string Dnscache_file_or_dir - path to Dnscache or directory of Dnscache files

Returns:
list of Dnscache filenames, -1 if fatal error
"""
def CreateDnscacheFileList(Dnscache_file_or_dir):

    logging.debug('+++ CreateDnscacheFileList(' + Dnscache_file_or_dir + ')')
        
    # Sanity checks
    if len(Dnscache_file_or_dir) == 0:
        logging.error('CreateDnscacheFileList(Dnscache_file_or_dir) - Dnscache_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(Dnscache_file_or_dir) == False:
        logging.error('CreateDnscacheFileList(Dnscache_file_or_dir) - Dnscache_file_or_dir param path does not exist.')
        return -1
    
    lstDnscacheFiles = []

    # Verify a single Dnscache log file
    if os.path.isfile(Dnscache_file_or_dir):
        res = IsDnscacheFile(Dnscache_file_or_dir)
        if res != -1 and res != False:
            lstDnscacheFiles.append(Dnscache_file_or_dir)
        else:
            logging.info('--- ' + Dnscache_file_or_dir + 'is not a Dnscache file.')
            print '--- ', Dnscache_file_or_dir, ' is not a Dnscache file.'
        return lstDnscacheFiles

    # Verify a dir of Dnscache output files
    dir_list = os.listdir(Dnscache_file_or_dir)
    for afile in dir_list:
        res = IsDnscacheFile(Dnscache_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstDnscacheFiles.append(Dnscache_file_or_dir + '\\' + afile)
        else:
            print '---', Dnscache_file_or_dir + '\\' + afile, 'is not an Dnscache output file.'
    
    return lstDnscacheFiles


"""
Verify Dnscache file or directory
Parameters:
string full_path - path to Dnscache file or directory of Dnscache files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyDnscacheFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_dnscache_table_schema)
            return 0
        except:
            logging.error('--- Error creating dnscache table in SQLite3 database.')
            print '--- Error creating dnscache table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the Dnscache table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS dnscache')
            g_conSQLite.execute(sqlite_dnscache_table_schema)
            return 0
        except:
            logging.error('--- Error dropping dnscache table from SQLite3 database.')
            print '--- Error dropping dnscache table from SQLite3 database.'
            return -1

    # Make sure Dnscache table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM dnscache;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating dnscache table in SQLite3 database.')
        g_conSQLite.execute(sqlite_dnscache_table_schema)
        
    return 0


"""
Verifies a file is a Dnscache output file
Returns:
    -1 if there was an error
    False if file is not a Dnscache output file
"""
def IsDnscacheFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid Dnscache file
    # We look for the field row within the first 10 lines of the file
    Dnscache_file = None
    try:
        Dnscache_file = file(path, 'r')
        for x in range(10):
            sig = Dnscache_file.readline()
            if sig.find('Windows IP Configuration') >= 0:
                Dnscache_file.close()
                return True
    except:
        Dnscache_file.close()
        return -1

    Dnscache_file.close()    
    return False

"""
Load Dnscache output into Dnscache table
Parameters:
string Dnscache_file     - Dnscache file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadDnscacheFiles(Dnscache_file, con):
    global g_ParseErrors
    global g_InsertErrors
    row_count = 0

    # Sanity checks
    if len(Dnscache_file) == 0:
        logging.error('--- LoadDnscacheFiles() - Dnscache_file parameter is empty.')
        return -1
    if os.path.exists(Dnscache_file) == False:
        logging.error('--- LoadDnscacheFiles() - Dnscache_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadDnscacheFiles() - con parameter is not valid.')
        return -1
    
    # Open the Dnscache file
    a_file = file(Dnscache_file, 'r')
    if a_file == None:
        logging.error('--- LoadDnscacheFiles() - error opening Dnscache_file ' + Dnscache_file + '.')
        return -1

    hostname = os.path.basename(Dnscache_file)
    if hostname.find('_') > 0:
        hostname = hostname.split('_')[0]
    
    cur = con.cursor()
    row_count = 0
    err_count = 0
    ins_count = 0

    while 1:
        x = a_file.readline()
        if x == "":
            break
        # Strip ', " , \n
        x = x.replace("'", '')
        x = x.replace('\n', '')
        # Ignore empty rows
        if len(x) == 0:
            continue
       
        ## Ignore header rows
        if x.find('Windows IP Configuration') >= 0:
            continue

        if x.find('Record Name') < 0:
            continue
        else:
            x = x.strip()
         
        row_count += 1 
        try:
            rec_name = ""
            rec_type = ""
            timetolive = ""
            data_len = ""
            section = ""
            ptr_record = ""
            a_record = ""
            
            # Record Name
            assert 'Record Name' in x
            rn = x
            rn = rn.replace('\n', '')
            rn = rn.split(':')
            rn = rn[1].strip()
            rec_name = rn
            # Record Type
            while 1:
                rt = a_file.readline()
                if rt == "":
                    break
                rt = rt.replace('\n', '')
                if len(rt) == 0:
                    continue
                assert 'Record Type' in rt
                rt = rt.split(':')
                rt = rt[1].strip()
                rec_type = rt
                break
            # Time to live
            while 1:
                ttl = a_file.readline()
                if ttl == "":
                    break
                ttl = ttl.replace('\n', '')
                if len(ttl) == 0:
                    continue
                assert 'Time To Live' in ttl
                ttl = ttl.split(':')
                ttl = ttl[1].strip()
                timetolive = ttl
                break
            # Data Length
            while 1:
                dl = a_file.readline()
                if dl == "":
                    break
                dl = dl.replace('\n', '')
                if len(dl) == 0:
                    continue
                assert 'Data Length' in dl
                dl = dl.split(':')
                dl = dl[1].strip()
                data_len = dl
                break
            # Section
            while 1:
                sec = a_file.readline()
                if sec == "":
                    break
                sec = sec.replace('\n', '')
                if len(sec) == 0:
                    continue
                assert 'Section' in sec
                sec = sec.split(':')
                sec = sec[1].strip()
                section = sec
                break
            # PTR records
            aline = a_file.readline()
            aline = aline.replace('\n', '')
            if len(aline) == 0:
                aline = a_file.readline()
            if 'PTR Record' in aline:
                ptr = aline.replace('\n', '')
                ptr = ptr.split(':')
                ptr = ptr[1].strip()
                ptr_record = ptr
            else:
                ptr_record = ''
            # A Records
            if 'A (Host) Record' in aline:
                arec = aline.replace('\n', '')
                arec = arec.split(':')
                arec = arec[1].strip()
                a_record = arec
            else:
                a_record = ''
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue    

        try:
            if timetolive == "":
                timetolive = "-1"
            if data_len == "":
                data_len = "-1"
            ins_string = 'insert into dnscache values(NULL,'
            ins_string += S_QUOTE + hostname + S_QUOTE + COMMA
            ins_string += S_QUOTE + rec_name + S_QUOTE + COMMA
            ins_string += S_QUOTE + rec_type + S_QUOTE + COMMA
            ins_string += timetolive + COMMA
            ins_string += data_len + COMMA
            ins_string += S_QUOTE + section + S_QUOTE + COMMA
            ins_string += S_QUOTE + ptr_record + S_QUOTE + COMMA
            ins_string += S_QUOTE + a_record + S_QUOTE +')'
            
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
    global g_strDnscacheFileorDir
    global g_logPath

    parser = argparse.ArgumentParser(description='Import ipconfig /displaydns output into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('logpath', help = 'Path to the Log storage directory.')
    parser.add_argument('dnscache_file_or_dir', help = 'dnscache output file or directory of Dnscache output files.')
    
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
    g_strDnscacheFileorDir = os.path.join(results.dnscache_file_or_dir,"network","dnscache")

    return 0

if __name__ == "__main__":
    main()

