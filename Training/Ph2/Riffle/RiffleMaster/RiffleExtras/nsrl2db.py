"""
/////////////////////////////////////////////////////////////////////////////
// Name:        nsrl2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-12-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-01-29 17:49:12 -0800 (Sun, 29 Jan 2012) $
$Revision: 1341 $
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
 *  nsrl2db.py
 *  This script loads the Nsrl unique hash data set into a database for comparison.
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
VerifyNsrlDir(full_path):                    Verifies nsrl directory exists
OpenOrCreateDB(db_name, user, pwd):          Opens or creates a database
OpenSQLiteDB(db_path):                       Opens or creates an SQLite3 database
OpenMySQLDB(db_name, user, pwd):             Opens or creates a MySQL database
IsNSRLFile(path):                            Verifies a file is a NSRL file
LoadNSRLHashFile(nsr_file, con):             Loads a NSRL hash file into a database
LoadNSRLMfgFile(nsr_file, con):              Loads a NSRL mfg file into a database
LoadNSRLProdFile(nsr_file, con):             Loads a NSRL prod file into a database
LoadNSRLOSFile(nsr_file, con):               Loads a NSRL os file into a database
GetCommandLineArgs():                        Processes command line parms
"""

"""
NSRL File
=========
"SHA-1"
"MD5"
"CRC32"
"FileName"
"FileSize" 
"ProductCode" 
"OpSystemCode"
"SpecialCode"

MFG File
=========
"MfgCode",
"MfgName"

OS File
=======
"OpSystemCode",
"OpSystemName",
"OpSystemVersion",
"MfgCode"

Product
========
"ProductCode",
"ProductName",
"ProductVersion",
"OpSystemCode",
"MfgCode",
"Language",
"ApplicationType"
"""

# Database schemas
sqlite_nsrl_hash_table_schema = """
Create Table nsrl_hash (ID INTEGER PRIMARY KEY AUTOINCREMENT,
SHA1 TEXT,
MD5 TEXT,
CRC32 TEXT,
FileName TEXT,
FileSize INT,
ProdCode INT, 
OSCode TEXT,
SpecCode TEXT);
"""

sqlite_nsrl_mfg_table_schema = """
Create Table nsrl_mfg (ID INTEGER PRIMARY KEY AUTOINCREMENT,
MfgCode TEXT,
MfgName TEXT);
"""

sqlite_nsrl_os_table_schema = """
Create Table nsrl_os (ID INTEGER PRIMARY KEY AUTOINCREMENT,
OSCode TEXT,
OSName TEXT,
OSVer TEXT,
OSMfg TEXT);
"""

sqlite_nsrl_prod_table_schema = """
Create Table nsrl_prod (ID INTEGER PRIMARY KEY AUTOINCREMENT,
ProdCode TEXT,
ProdName TEXT,
ProdVer TEXT,
OSCode TEXT,
MfgCode TEXT,
Language TEXT,
AppType TEXT);
"""

## MySQL schemas
mysql_nsrl_hash_table_schema = """
Create Table nsrl_hash (ID INT NOT NULL AUTO_INCREMENT,
SHA1 TEXT,
MD5 TEXT,
CRC32 TEXT,
FileName TEXT,
FileSize INT,
ProdCode INT, 
OSCode TEXT,
SpecCode TEXT,
PRIMARY KEY (ID));
"""

mysql_nsrl_mfg_table_schema = """
Create Table nsrl_mfg (ID INT NOT NULL AUTO_INCREMENT,
MfgCode TEXT,
MfgName TEXT,
PRIMARY KEY (ID));
"""

mysql_nsrl_os_table_schema = """
Create Table nsrl_os (ID INT NOT NULL AUTO_INCREMENT,
OSCode TEXT,
OSName TEXT,
OSVer TEXT,
OSMfg TEXT,
PRIMARY KEY (ID));
"""

mysql_nsrl_prod_table_schema = """
Create Table nsrl_prod (ID INT NOT NULL AUTO_INCREMENT,
ProdCode TEXT,
ProdName TEXT,
ProdVer TEXT,
OSCode TEXT,
MfgCode TEXT,
Language TEXT,
AppType TEXT,
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
g_strNSRLDir = ''

# Other globals
S_QUOTE = '\''
COMMA = ','
g_conSQLite    = None
g_conMySQL     = None
g_LogLevel     = logging.INFO
g_ParseErrors  = None
g_InsertErrors = None

def main():
    global g_ParseErrors
    global g_InsertErrors

    # Set log levels
    logging.basicConfig(format='%(asctime)s %(message)s', filename='nsrl2db_log.txt', filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file('nsrl2db_parse_errors.txt', 'w')
    g_InsertErrors = file('nsrl2db_insert_errors.txt', 'w')
    
    # Get command line args
    logging.debug('+++ Getting command line args.')
    if GetCommandLineArgs() != 0:
        return -1

    # Verify passed in Nsrl dir exists
    if VerifyNsrlDir(g_strNSRLDir) != 0:
        logging.error('--- Directory ' + g_strNSRLDir + 'does not exist.') 
        print 'Directory ', g_strNSRLDir, 'does not exist.'
        return -1

    # Open or create the Nsrl database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    if g_bSQLiteDB == True:
        logging.debug('SQLite3 LoadNSRLFiles() - ' + g_strNSRLDir)
        print '+++ Loading NSRL fileset into SQLite3 database...'
        LoadNSRLFiles(g_conSQLite)

    if g_bMySQLDB == True:
        logging.debug('MySQL LoadNSRLFiles() - ' + g_strNSRLDir)
        print '+++ Loading NSRL fileset into MySQL database...'
        LoadNSRLFiles(g_conMySQL)

    logging.info('+++ Closing database.')
    print '+++ Loading of NSRL fileset completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0


"""
Loads the four NSRL files in the unique hash fileset into a database
Parameters:
dbconnection con - connection to an open SQLite3 or MySQL database

Returns:
0 if no error, -1 if otherwise
"""
def LoadNSRLFiles(con):

    # Sanity checks
    if con == None:
        logging.error('--- LoadNSRLFiles() - con parameter is not valid.')
        return -1

    LoadNSRLHashFile(g_strNSRLDir + '\\NSRLFile.txt', con)
    LoadNSRLMfgFile(g_strNSRLDir + '\\NSRLMfg.txt', con)
    LoadNSRLProdFile(g_strNSRLDir + '\\NSRLProd.txt', con)
    LoadNSRLOSFile(g_strNSRLDir + '\\NSRLOS.txt', con)

    return 0

"""
Verify NSRL directory has correct files
Parameters:
string full_path - path to NSRL directory containing NSRL data files
    NSRLFile.txt
    NSRLMfg.txt
    NSRLOS.txt
    MSRLProd.txt

Returns:
0 if verified, -1 if invalid directory
"""
def VerifyNsrlDir(full_path):

    if len(full_path) == 0:
        return -1
    
    if os.path.exists(full_path) == False:
        return -1

    if not os.path.exists(full_path + '\\NSRLFile.txt'):
        return -1
    if not os.path.exists(full_path + '\\NSRLMfg.txt'):
        return -1
    if not os.path.exists(full_path + '\\NSRLOS.txt'):
        return -1
    if not os.path.exists(full_path + '\\NSRLProd.txt'):
        return -1

    return 0;

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
            g_conSQLite.execute(sqlite_nsrl_hash_table_schema)
            g_conSQLite.execute(sqlite_nsrl_mfg_table_schema)
            g_conSQLite.execute(sqlite_nsrl_os_table_schema)
            g_conSQLite.execute(sqlite_nsrl_prod_table_schema)
            return 0
        except:
            logging.error('--- Error creating NSRL tables in SQLite3 database.')
            print '--- Error creating NSRL table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the Nsrl tables if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_hash')
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_mfg')
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_os')
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_prod')
            g_conSQLite.execute(sqlite_nsrl_hash_table_schema)
            g_conSQLite.execute(sqlite_nsrl_mfg_table_schema)
            g_conSQLite.execute(sqlite_nsrl_os_table_schema)
            g_conSQLite.execute(sqlite_nsrl_prod_table_schema)
            return 0
        except:
            logging.error('--- Error dropping NSRL tables from SQLite3 database.')
            print '--- Error dropping NSRL tables from SQLite3 database.'
            return -1

    # Make sure NSRL tables exists
    try:
        g_conSQLite.execute("SELECT * FROM nsrl_hash LIMIT 5;")
    except sqlite3.OperationalError, err:
        g_conSQLite.execute(sqlite_nsrl_hash_table_schema)
    try:
        g_conSQLite.execute("SELECT count(*) FROM nsrl_mfg;")
    except:
        g_conSQLite.execute(sqlite_nsrl_mfg_table_schema)
    try:
        g_conSQLite.execute("SELECT count(*) FROM nsrl_os;")
    except:
        g_conSQLite.execute(sqlite_nsrl_os_table_schema)
    try:
        g_conSQLite.execute("SELECT count(*) FROM nsrl_prod;")
    except:
        g_conSQLite.execute(sqlite_nsrl_prod_table_schema)
        
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
            cur.execute(mysql_Nsrl_table_schema)
            return 0
        except:
            logging.error('--- Error creating NSRL table in MySQL database')
            print '--- Error creating NSRL tables in MySQL database'
            g_conMySQL = None
            return -1

    # Empty the Nsrl tables if requested
    if g_bEmptyDB == True:
        try:
            cur.execute('USE ' + db_name + ';')
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_hash')
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_mfg')
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_os')
            g_conSQLite.execute('DROP TABLE IF EXISTS nsrl_prod')
            g_conSQLite.execute(mysql_nsrl_hash_table_schema)
            g_conSQLite.execute(mysql_nsrl_mfg_table_schema)
            g_conSQLite.execute(mysql_nsrl_os_table_schema)
            g_conSQLite.execute(mysql_nsrl_prod_table_schema)
            return 0
        except:
            logging.error('--- Error dropping NSRL tables from MySQL database.')
            print '--- Error dropping NSRL tables from MySQL database.'
            g_conSQLite = None
            return -1

    # Make sure NSRL tables exists
    try:
        cur.execute('USE ' + db_name + ';')
        hash_tbl_exists = False
        mfg_tbl_exists = False
        os_tbl_exists = False
        prod_tbl_exists = False

        cur.execute("SHOW tables;")
        db_tuples = cur.fetchall()
        for x in db_tuples:
            if 'nsrl_hash' in x:
                hash_tbl_exists = True
            if 'nsrl_mfg' in x:
                mfg_tbl_exists = True
            if 'nsrl_os' in x:
                os_tbl_exists = True
            if 'nsrl_prod' in x:
                prod_tbl_exists = True

        if hash_tbl_exists == False:
            cur.execute(mysql_nsrl_hash_table_schema)
        if mfg_tbl_exists == False:
            cur.execute(mysql_nsrl_mfg_table_schema)
        if os_tbl_exists == False:
            cur.execute(mysql_nsrl_os_table_schema)
        if prod_tbl_exists == False:
            cur.execute(mysql_nsrl_prod_table_schema)

        return 0
    except:
        logging.error('--- Error creating NSRL tables in MySQL database.')
        print '--- Error creating NSRL tables in MySQL database.'
        g_conSQLite = None
        return -1
   
    return 0

"""
Verifies a file is an NSRL file
Returns:
    -1 if there was an error
    False if file is not an NSRL file
"""
def IsNSRLFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid NSRL file
    NSRL_File = None
    try:
        NSRL_File = file(path, 'r')
        sig = NSRL_File.readline()
        if sig.find('SHA-1') >= 0 and sig.find('MD5') >= 0 and sig.find('FileName') >= 0 and sig.find('ProductCode') >= 0 \
        and sig.find('OpSystemCode') >= 0 and sig.find('SpecialCode') >= 0:
            NSRL_File.close()
            return True

        if sig.find('MfgCode') >= 0 and sig.find('MfgName') >= 0:
            NSRL_File.close()
            return True

        if sig.find('OpSystemCode') >= 0 and sig.find('OpSystemName') >= 0 and sig.find('OpSystemVersion') >= 0 and sig.find('MfgCode') >= 0:
            NSRL_File.close()
            return True

        if sig.find('ProductCode') >= 0 and sig.find('ProductName') >= 0 and sig.find('ProductVersion') >= 0 and sig.find('OpSystemCode') >= 0 \
        and sig.find('MfgCode') >= 0 and sig.find('Language') >= 0 and sig.find('ApplicationType') >= 0:
            NSRL_File.close()
            return True
    except:
        NSRL_File.close()
        return -1

    NSRL_File.close()    
    return False


def LoadNSRLHashFile(nsrl_file, con):
    global g_ParseErrors
    global g_InsertErrors
    
    # Sanity checks
    if len(nsrl_file) == 0:
        logging.error('--- LoadNSRLHashFile() - nsrl_file parameter is empty.')
        return -1
    if os.path.exists(nsrl_file) == False:
        logging.error('--- LoadNSRLHashFile() - nsrl_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadNSRLHashFile() - con parameter is not valid.')
        return -1
    
    # Open the NSRL file
    a_file = file(nsrl_file, 'r')
    if a_file == None:
        logging.error('--- LoadNSRLHashFile() - error opening NSRL_file ' + nsrl_file + '.')
        return -1
    
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
        if 'SHA-1' in x and 'MD5' in x:
            continue

        if x.find('"') < 0:
            continue
        
        row_count += 1

        ## Populate the NSRL hash table
        try:
            idx1 = 0
            idx2 = x.find('"', idx1+1)
            sha1 = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            md5  =  x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            crc  =  x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            fname  =  x[idx1:idx2].replace('"', '')
            idx1 = x.find(',',idx2)
            idx2 = x.find(',', idx1+1)
            fsize = x[idx1+1:idx2]
            idx1 = x.find(',',idx2)
            idx2 = x.find(',', idx1+1)
            pcode = x[idx1+1:idx2]
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            opcode =  x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            spcode =  x[idx1:idx2].replace('"', '')
            if spcode == '"':
                spcode = ''
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
       
        try:
            ins_string = 'insert into nsrl_hash values(NULL,'
            ins_string += S_QUOTE + sha1 + S_QUOTE + COMMA
            ins_string += S_QUOTE + md5 + S_QUOTE + COMMA
            ins_string += S_QUOTE + crc + S_QUOTE + COMMA            
            ins_string += S_QUOTE + fname.replace("'", "''") + S_QUOTE + COMMA
            ins_string += fsize + COMMA
            ins_string += pcode + COMMA
            ins_string += S_QUOTE + opcode + S_QUOTE + COMMA
            ins_string += S_QUOTE + spcode + S_QUOTE + ')'
            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count += 1
            continue

    con.commit()
    cur.close()
    a_file.close()
    
    print '+++', 'NSRL hash load completed:', row_count, 'total rows processed.'
    print '+++', row_count, 'total rows processed.'
    print '---', err_count, 'parse errors.'
    print '---', ins_count, 'database insertion errors.'        


def LoadNSRLMfgFile(nsrl_file, con): 
    global g_ParseErrors
    global g_InsertErrors
    
    # Sanity checks
    if len(nsrl_file) == 0:
        logging.error('--- LoadNSRLMfgFile() - nsrl_file parameter is empty.')
        return -1
    if os.path.exists(nsrl_file) == False:
        logging.error('--- LoadNSRLMfgFile() - nsrl_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadNSRLMfgFile() - con parameter is not valid.')
        return -1
    
    # Open the NSRL file
    a_file = file(nsrl_file, 'r')
    if a_file == None:
        logging.error('--- LoadNSRLMfgFile() - error opening nsrl_file ' + nsrl_file + '.')
        return -1
    
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
        if 'MfgCode' in x and 'MfgName' in x:
            continue

        if x.find('"') < 0:
            continue
        
        row_count += 1

        ## Populate the NSRL mfg table
        try:
            idx1 = 0
            idx2 = x.find('"', idx1+1)
            mfgcode = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            mfgname = x[idx1:idx2].replace('"', '')
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
       
        try:
            ins_string = 'insert into nsrl_mfg values(NULL,'
            ins_string += S_QUOTE + mfgcode.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + mfgname.replace("'", "''") + S_QUOTE + ')'

            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count += 1
            continue

    con.commit()
    cur.close()
    a_file.close()
    print '+++', 'NSRL mfg load completed:', row_count, 'total rows processed.'
    print '+++', row_count, 'total rows processed.'
    print '---', err_count, 'parse errors.'
    print '---', ins_count, 'database insertion errors.'        


def LoadNSRLProdFile(nsrl_file, con):
    global g_ParseErrors
    global g_InsertErrors
    
    # Sanity checks
    if len(nsrl_file) == 0:
        logging.error('--- LoadNSRLProdFile() - nsrl_file parameter is empty.')
        return -1
    if os.path.exists(nsrl_file) == False:
        logging.error('--- LoadNSRLProdFile() - nsrl_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadNSRLProdFile() - con parameter is not valid.')
        return -1
    
    # Open the NSRL file
    a_file = file(nsrl_file, 'r')
    if a_file == None:
        logging.error('--- LoadNSRLProdFile() - error opening NSRL_file ' + nsr_file + '.')
        return -1
    
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
        if 'ProductCode' in x and 'ProductName' in x:
            continue

        if x.find('"') < 0:
            continue
        
        row_count += 1

        ## Populate the NSRL product table
        try:
            idx1 = 0
            idx2 = x.find(',', idx1+1)
            prodcode = x[idx1:idx2]
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            prodname = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            prodver = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            opcode = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            mfgcode = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            lang = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            apptype = x[idx1:idx2].replace('"', '')
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
      
        try:
            ins_string = 'insert into nsrl_prod values(NULL,'
            ins_string += S_QUOTE + prodcode.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + prodname.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + prodver.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + opcode.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + mfgcode.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + lang.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + apptype.replace("'", "''") + S_QUOTE + ')'

            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count += 1
            continue

    con.commit()
    cur.close()
    print '+++', 'NSRL prod load completed:', row_count, 'total rows processed.'
    print '+++', row_count, 'total rows processed.'
    print '---', err_count, 'parse errors.'
    print '---', ins_count, 'database insertion errors.'        


def LoadNSRLOSFile(nsrl_file, con):
    global g_ParseErrors
    global g_InsertErrors
    
    # Sanity checks
    if len(nsrl_file) == 0:
        logging.error('--- LoadNSRLOSFile() - nsrl_file parameter is empty.')
        return -1
    if os.path.exists(nsrl_file) == False:
        logging.error('--- LoadNSRLOSFile() - nsrl_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadNSRLOSFile() - con parameter is not valid.')
        return -1
    
    # Open the NSRL OS file
    a_file = file(nsrl_file, 'r')
    if a_file == None:
        logging.error('--- LoadNSRLOSFile() - error opening NSRL_file ' + nsr_file + '.')
        return -1
    
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
        if 'OpSystemCode' in x and 'OpSystemName' in x:
            continue

        if x.find('"') < 0:
            continue
        
        row_count += 1

        ## Populate the NSRL OS table
        try:
            idx1 = 0
            idx2 = x.find('"', idx1+1)
            oscode = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            osname = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            osver = x[idx1:idx2].replace('"', '')
            idx1 = x.find('"',idx2+1)
            idx2 = x.find('"', idx1+1)
            osmfg = x[idx1:idx2].replace('"', '')
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
       
        try:
            ins_string = 'insert into nsrl_os values(NULL,'
            ins_string += S_QUOTE + oscode.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + osname.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + osver.replace("'", "''") + S_QUOTE + COMMA
            ins_string += S_QUOTE + osmfg.replace("'", "''") + S_QUOTE + ')'

            cur.execute(ins_string)
        except:
            g_InsertErrors.write(ins_string + '\n')
            ins_count += 1
            continue

    con.commit()
    cur.close()
    print '+++', 'NSRL OS load completed:', row_count, 'total rows processed.'
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
    global g_bMySQLDB
    global g_strUserName
    global g_strUserPwd
    global g_strNSRLDir

    parser = argparse.ArgumentParser(description='Import NSRL unique hash file set into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-m', dest='mysql_db', action='store_true', help = 'use MySQL database engine.')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('NSRL_dir', help = 'Directory of NSRL unique hash file set files.')
    
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
    g_strNSRLDir = results.NSRL_dir

    return 0


if __name__ == "__main__":
    main()

