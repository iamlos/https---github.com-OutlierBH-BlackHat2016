"""
/////////////////////////////////////////////////////////////////////////////
// Name:        geoip2db.py
// Purpose:     Forensic analysis utility
// Author:      Michael G. Spohn
// Modified by:
// Created:     01-12-2012
// Copyright:   (c) Michael G. Spohn
// License:
/////////////////////////////////////////////////////////////////////////////
/*
$LastChangedDate: 2012-01-21 16:05:15 -0800 (Sat, 21 Jan 2012) $
$Revision: 1320 $
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
 *  geoip2db.py
 *  This script loads a MaxMind GeoIP file created by my GeoIP.py python script into a database for analysis.
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
CreateGeoIPFileList(GeoIP_file_or_dir):      Creates a list of GeoIP.py output files to process
VerifyGeoIPFileOrDir(full_path):             Verifies GeoIP file or directory exist
OpenOrCreateDB(db_name, user, pwd):          Opens or creates a database
OpenSQLiteDB(db_path):                       Opens or creates an SQLite3 database
OpenMySQLDB(db_name, user, pwd):             Opens or creates a MySQL database
IsGeoIPFile(path):                           Verifies a file is a GeoIP output file
LoadGeoIPFile(GeoIP_file, con):              Loads a GeoIP file into a database
GetCommandLineArgs():                        Processes command line parms
"""

"""
MaxMind GeoIp Fields
=================
IP Addresss
Country Code
Country
State
Region_Code
State_Region
City
Latitude
Longitude
Metro_Code
Area_Code
Time_Zone
Continent
Postal_Code
ISP
Net_Block
Domain
ASN
Net_Speed
User_Type
Accuracy_Radius
Country_Confidence
City_Confidence
Region_Confidence
Postal_Confidence
Error
"""

# Database schemas
sqlite_geoip_table_schema = """
Create Table geoip (ID INTEGER PRIMARY KEY AUTOINCREMENT,
Country_Code TEXT,
Country TEXT,
State TEXT,
Region_Code TEXT,
State_Region TEXT,
City TEXT,
Latitude TEXT,
Longitude TEXT,
Metro_Code TEXT,
Area_Code TEXT,
Time_Zone TEXT,
Continent TEXT,
Postal_Code TEXT,
ISP TEXT,
Net_Block TEXT,
Domain TEXT,
ASN TEXT,
Net_Speed TEXT,
User_Type TEXT,
Accuracy_Radius TEXT,
Country_Confidence TEXT,
City_Confidence TEXT,
Region_Confidence TEXT,
Postal_Confidence TEXT,
Error TEXT);
"""

mysql_geoip_table_schema = """
Create Table geoip (ID INT NOT NULL AUTO_INCREMENT,
Country_Code TEXT,
Country TEXT,
State TEXT,
Region_Code TEXT,
State_Region TEXT,
City TEXT,
Latitude TEXT,
Longitude TEXT,
Metro_Code TEXT,
Area_Code TEXT,
Time_Zone TEXT,
Continent TEXT,
Postal_Code TEXT,
ISP TEXT,
Net_Block TEXT,
Domain TEXT,
ASN TEXT,
Net_Speed TEXT,
User_Type TEXT,
Accuracy_Radius TEXT,
Country_Confidence TEXT,
City_Confidence TEXT,
Region_Confidence TEXT,
Postal_Confidence TEXT,
Error TEXT,
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
g_strGeoIPFileorDir = ''

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
    logging.basicConfig(format='%(asctime)s %(message)s', filename='geoip2db_log.txt', filemode='w', level=g_LogLevel)

    # Open the SQL error files
    g_ParseErrors = file('geoip2db_log.txt', 'w')
    g_InsertErrors = file('geoip2db_log.txt', 'w')
    
    # Get command line args
    logging.debug('+++ Getting command line args.')
    if GetCommandLineArgs() != 0:
        return -1

    # Verify passed in GeoIP file or dir exists
    if VerifyGeoIPFileOrDir(g_strGeoIPFileorDir) != 0:
        logging.error('--- File or directory ' + g_strGeoIPFileorDir + 'does not exist.') 
        print 'File or directory ', g_strGeoIPFileorDir, 'does not exist.'
        return -1

    # Open or create the GeoIP database
    print '+++ Opening/creating database', g_strDBName, '...'
    if OpenOrCreateDB(g_strDBName, g_strUserName, g_strUserPwd) != 0:
        logging.debug('+++ OpenOrCreateDB(' + g_strDBName + ',' + g_strUserName + ',' + g_strUserPwd + ')')
        return -1

    # Create a list of GeoIP logs to process
    lstGeoIPFileList = CreateGeoIPFileList(g_strGeoIPFileorDir)
    logging.debug('+++ CreateGeoIPFileList(' + g_strGeoIPFileorDir + ')')
    if len(lstGeoIPFileList) == 0:
         logging.error('--- No GeoIP files were found to process.')
         print 'No GeoIP files were found.'
         return -1
    if len(lstGeoIPFileList) == 1: 
        print '+++ There is', str(len(lstGeoIPFileList)), 'GeoIP files to process...'
    if len(lstGeoIPFileList) > 1: 
        print '+++ There are', str(len(lstGeoIPFileList)), 'GeoIP files to process...'

    for afile in lstGeoIPFileList:
        if g_bSQLiteDB == True:
            logging.debug('SQLite3 LoadEvents(' + g_strGeoIPFileorDir + '\\' + afile + ')')
            print '+++ Loading GeoIP file', afile, 'into SQLite3 database...'
            LoadGeoIPFile(afile, g_conSQLite)

        if g_bMySQLDB == True:
            logging.debug('MySQL LoadEvents(' + g_strGeoIPFileorDir + '\\' + afile + ')')
            print '+++ Loading GeoIP file', afile, 'into MySQL database...'
            LoadGeoIPFile(afile, g_conMySQL)
            
    logging.info('+++ Closing database.')
    print '+++ Loading of GeoIP files completed...'
    if g_conSQLite:
        g_conSQLite.close()
    if g_conMySQL:
        g_conMySQL.close()

    g_ParseErrors.close()
    g_InsertErrors.close()
    
    return 0

"""
Create a list of GeoIP files to process
string GeoIP_file_or_dir - path to GeoIP or directory of GeoIP files

Returns:
list of GeoIP filenames, -1 if fatal error
"""
def CreateGeoIPFileList(GeoIP_file_or_dir):

    logging.debug('+++ CreateGeoIPFileList(' + GeoIP_file_or_dir + ')')
        
    # Sanity checks
    if len(GeoIP_file_or_dir) == 0:
        logging.error('CreateGeoIPFileList(GeoIP_file_or_dir) - GeoIP_file_or_dir param is empty.')
        return -1
    
    if os.path.exists(GeoIP_file_or_dir) == False:
        logging.error('CreateGeoIPFileList(GeoIP_file_or_dir) - GeoIP_file_or_dir param path does not exist.')
        return -1
    
    lstGeoIPFiles = []

    # Verify a single GeoIP log file
    if os.path.isfile(GeoIP_file_or_dir):
        res = IsGeoIPFile(GeoIP_file_or_dir)
        if res != -1 and res != False:
            lstGeoIPFiles.append(GeoIP_file_or_dir)
        else:
            logging.info('--- ' + GeoIP_file_or_dir + 'is not a GeoIP output file.')
            print '--- ', GeoIP_file_or_dir, ' is not a GeoIP output file.'
        return lstGeoIPFiles

    # Verify a dir of GeoIP output files
    dir_list = os.listdir(GeoIP_file_or_dir)
    for afile in dir_list:
        res = IsGeoIPFile(GeoIP_file_or_dir + '\\' + afile)
        if res != -1 and res != False:
            lstGeoIPFiles.append(GeoIP_file_or_dir + '\\' + afile)
        else:
            print '---', GeoIP_file_or_dir + '\\' + afile, 'is not a GeoIP output file.'
    
    return lstGeoIPFiles

"""
Verify GeoIP file or directory
Parameters:
string full_path - path to GeoIP file or directory of GeoIP files

Returns:
0 if verified, -1 if invalid file or directory
"""
def VerifyGeoIPFileOrDir(full_path):
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
            g_conSQLite.execute(sqlite_geoip_table_schema)
            return 0
        except:
            logging.error('--- Error creating geoip table in SQLite3 database.')
            print '--- Error creating geoip table in SQLite3 database.'
            return -1

    # Open the database if it exists
    try:
        g_conSQLite = sqlite3.connect(db_path)
    except:
        logging.error('--- Error opening SQLite3 database ', db_path + '.')
        print '--- Error opening SQLite3 database ', db_path +'.'
        return -1

    # Empty the GeoIP table if requested
    if g_bEmptyDB == True:
        try:
            g_conSQLite.execute('DROP TABLE IF EXISTS geoip')
            g_conSQLite.execute(sqlite_geoip_table_schema)
            return 0
        except:
            logging.error('--- Error dropping geoip table from SQLite3 database.')
            print '--- Error dropping geoip table from SQLite3 database.'
            return -1

    # Make sure GeoIP table exists
    try:
        g_conSQLite.execute("SELECT count(*) FROM geoip LIMT 5;")
    except sqlite3.OperationalError, err:
        logging.info('+++ Creating geoip table in SQLite3 database.')
        g_conSQLite.execute(sqlite_geoip_table_schema)
        
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
            cur.execute(mysql_geoip_table_schema)
            return 0
        except:
            logging.error('--- Error creating geoip table in MySQL database')
            print '--- Error creating geoip table in MySQL database'
            g_conMySQL = None
            return -1

    # Empty the geoip table if requested
    if g_bEmptyDB == True:
        try:
            cur.execute('USE ' + db_name + ';')
            cur.execute('DROP TABLE if exists geoip;')
            cur.execute(mysql_geoip_table_schema)
            return 0
        except:
            logging.error('--- Error dropping geoip table from MySQL database.')
            print '--- Error dropping geoip table from MySQL database.'
            g_conSQLite = None
            return -1

    # Make sure GeoIP table exists
    try:
        cur.execute('USE ' + db_name + ';')
        tbl_exists = False
        cur.execute("SHOW tables;")
        db_tuples = cur.fetchall()
        for x in db_tuples:
            if 'geoip' in x:
                tbl_exists = True
        if tbl_exists == False:
            cur.execute(mysql_geoip_table_schema)
            return 0
    except:
        logging.error('--- Error dropping geoip table from MySQL database.')
        print '--- Error dropping geoip table from MySQL database.'
        g_conSQLite = None
        return -1
   
    return 0

"""
Verifies a file is an GeoIP output file
Returns:
    -1 if there was an error
    False if file is not an GeoIP file
"""
def IsGeoIPFile(path):
    if os.path.exists(path) == False:
        return -1

    # We don't do dirs
    if os.path.isdir(path):
        return -1
        
    # Confirm we have a valid GeoIP file
    GeoIP_file = None

    try:
        GeoIP_file = file(path, 'r')
        GeoIP_file.readline() # First line is empty
        GeoIP_file.readline() # Second line is run date
        sig = GeoIP_file.readline() # Second line is field header
        if sig.find('IP Addresss') >= 0 and sig.find('Country Code') >= 0 and sig.find('State/Region_Code') >= 0 and sig.find('State/Region') >= 0 \
        and sig.find('City') >= 0 and sig.find('Latitude') >= 0 and sig.find('Longitude') >= 0 \
        and sig.find('Metro_Code') >= 0 and sig.find('Area_Code') >= 0:
            GeoIP_file.close()
            return True
    except:
        GeoIP_file.close()
        return -1

    GeoIP_file.close()    
    return False

"""
Load GeoIp output file into geoip table
Parameters:
string GeoIP_file    - GeoIP file to load
Database Connection con  - Database connection object

Returns:
0 if success, -1 if error
"""
def LoadGeoIPFile(GeoIP_file, con):
    global g_ParseErrors
    global g_InsertErrors
    
    # Sanity checks
    if len(GeoIP_file) == 0:
        logging.error('--- LoadGeoIPFile() - GeoIP_file parameter is empty.')
        return -1
    if os.path.exists(GeoIP_file) == False:
        logging.error('--- LoadGeoIPFile() - GeoIP_file does not exist.')
        return -1
    if con == None:
        logging.error('--- LoadGeoIPFile() - con parameter is not valid.')
        return -1
    
    # Open the GeoIP file
    a_file = file(GeoIP_file, 'r')
    if a_file == None:
        logging.error('--- LoadGeoIPFile() - error opening GeoIP_file ' + GeoIP_file + '.')
        return -1
    
    cur = con.cursor()
    row_count = 0
    ins_count = 0
    err_count = 0
    idx1 = 0
    idx2 = 0

    # Read the header lines
    for x in range(5):
        h_line = a_file.readline()
        ## Ignore header row
        if 'IP Addresss' in h_line and 'Country Code' in h_line:
            break

    # Process the rest of the file
    for x in a_file:
        if len(x) == 0:
            continue
        # Clean up the row
        x = x.replace('\n', '')
        x = x.replace('"', '')
        x = x.replace("'", "''")

        row_count += 1
        a_row = x.split('\t')
    
    # Handle no IP found rows
        if len(a_row) == 2:
            ip = a_row[0]
            country_code = a_row[1]
            ins_string = 'insert into geoip values(NULL,'
            ins_string += S_QUOTE + ip + S_QUOTE + COMMA
            ins_string += S_QUOTE + country_code + S_QUOTE + COMMA
            ins_string += "'','','','','','','','','','','','','','','','','','','','','','','')"
            try:
                cur.execute(ins_string)
            except:
                g_InsertErrors.write(ins_string + '\n')
                ins_count += 1
                continue

            continue
          
        
        ## Populate the GeoIP table
        try:
            ip = a_row[0]
            country_code = a_row[1]
            country = a_row[2]
            state = a_row[3]
            reg_code = a_row[4]
            state = a_row[5]
            city = a_row[6]
            lat = a_row[7]
            long = a_row[8]
            metro = a_row[9]
            area_code = a_row[10]
            tz = a_row[11]
            continent = a_row[11]
            postal = a_row[12]
            isp = a_row[13]
            net_block = a_row[14]
            domain = a_row[15]
            asn = a_row[16]
            speed = a_row[17]
            user_type = a_row[18]
            accuracy = a_row[19]
            country_conf = a_row[20]
            city_conf = a_row[21]
            region_conf = a_row[22]
            postal_conf = a_row[23]
            error = a_row[24]
        except:
            g_ParseErrors.write('Line: ' + str(row_count) + '\n' + x + '\n')
            err_count += 1
            continue
       
        try:
            ins_string = 'insert into geoip values(NULL,'
            ins_string += S_QUOTE + ip + S_QUOTE + COMMA
            ins_string += S_QUOTE + country_code + S_QUOTE + COMMA
            ins_string += S_QUOTE + state + S_QUOTE + COMMA
            ins_string += S_QUOTE + reg_code + S_QUOTE + COMMA
            ins_string += S_QUOTE + state + S_QUOTE + COMMA
            ins_string += S_QUOTE + city + S_QUOTE + COMMA
            ins_string += S_QUOTE + lat + S_QUOTE + COMMA
            ins_string += S_QUOTE + long + S_QUOTE + COMMA
            ins_string += S_QUOTE + metro + S_QUOTE + COMMA
            ins_string += S_QUOTE + area_code + S_QUOTE + COMMA
            ins_string += S_QUOTE + tz + S_QUOTE +  COMMA
            ins_string += S_QUOTE + continent + S_QUOTE + COMMA
            ins_string += S_QUOTE + postal + S_QUOTE + COMMA
            ins_string += S_QUOTE + isp + S_QUOTE + COMMA
            ins_string += S_QUOTE + net_block + S_QUOTE + COMMA
            ins_string += S_QUOTE + domain + S_QUOTE + COMMA
            ins_string += S_QUOTE + asn + S_QUOTE + COMMA
            ins_string += S_QUOTE + speed + S_QUOTE + COMMA
            ins_string += S_QUOTE + user_type + S_QUOTE + COMMA
            ins_string += S_QUOTE + accuracy + S_QUOTE + COMMA
            ins_string += S_QUOTE + country_conf + S_QUOTE + COMMA
            ins_string += S_QUOTE + city_conf + S_QUOTE + COMMA
            ins_string += S_QUOTE + region_conf + S_QUOTE +  COMMA
            ins_string += S_QUOTE + postal_conf + S_QUOTE + COMMA
            ins_string += S_QUOTE + error + S_QUOTE + ')'
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
    global g_bMySQLDB
    global g_strUserName
    global g_strUserPwd
    global g_strGeoIPFileorDir

    parser = argparse.ArgumentParser(description='Import MaxMind GeoIP output into a database.')
    parser.add_argument('-V', action='version', version='%(prog)s 0.5')
    parser.add_argument('-m', dest='mysql_db', action='store_true', help = 'use MySQL database engine.')
    parser.add_argument('-l', dest='sqlite_db', action='store_false', help = 'use SQLite3 database engine.')
    parser.add_argument('-c', dest='create_db', action='store_true', help = 'create database if needed.')
    parser.add_argument('-e', dest='empty_db', action='store_true', help = 'empty database prior to loading.')
    parser.add_argument('-u', dest='user_name', default='', help = 'DB user name.')
    parser.add_argument('-p', dest='user_pwd', default='', help = 'DB user pwd.')
    parser.add_argument('db_name', help = 'database name.')
    parser.add_argument('geoip_file_or_dir', help = 'GeoIP.py output file or directory of GeoIP.py output files.')
    
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
    g_strGeoIPFileorDir = results.geoip_file_or_dir

    return 0


if __name__ == "__main__":
    main()

