single archive file extract:

c:\python27\python.exe <path to folder>\pyscripts\loadriffledb.py -x dbname.db3 <path to archive file>\archivename.7z


multiple archives: hunt_4_malware


c:\python27\python.exe <path to folder>\pyscripts\loadriffledb.py -x none.db3 C:\Users\Consultant\Desktop\test\tmpriffleload


single autorunsc file (and create db, or exclude -c if db exists):

c:\python27\python.exe <path to folder>\pyscripts\autorunsc2db.py -c dbname.db3 <path to archive folder>\tmpriffleload\XP-FF3F6B62E8AB_autorunsc.txt

multiple autorunsc files:

c:\python27\python.exe C:\Users\Consultant\Desktop\Riffle\pyscripts\mft2db.py C:\Users\Consultant\Desktop\Riffle\RiffleArchives\bh101112 C:\Users\Consultant\Desktop\Riffle\new\MFT

mft2db
autorunsc2db
md5deep2db
dnscache2db
netstat2db
schtasks2db
tasklist2db
tasklist_svc2db 

and etc...

You should only need to run a few load scripts to get where you want to be:

This is what I do:

+ autorunsc2db.py –c  dbname.db3 tmpRiffLoad 
+ md5deep2db.py dbname.db3 tmpRiffleLoad
app_evt2db dbname.db3 tmpRiffleLoad (See Notes)
sec_evt2db dbname.db3 tmpRiffleLoad (See Notes)
sys_evt2db dbname.db3 tmpRiffleLoad (See Notes)
+ mft2db.py dbname.db3 tmpRiffleLoad  (See Notes)
+ dnscache2db.py dbname.db3 tmpRiffleLoad
+ netstat2db.py dbname.db3 tmpRiffleLoad
+ mfeaplogs2db dbname.db3 tmpRiffleLoad (if you have MFE A/V)
+ mfeoaslogs2db dbname.db3 tmpRiffleLoad (ditto)
+ netstat2db.py dbname.db3 tmpRiffleLoad
+ schtasks2db.py dbname.db3 tmpRiffleLoad
+ tasklist2db.py dbname.db3 tmpRiffleLoad
+ tasklist_svc2db dbname.db3 tmpRiffleLoad


####NOTES

If you want the MFT data loaded there are a couple of steps:
-------------------------------------------------------------
1) Traverse to the tmpRiffle\MFT folder.
2) Drop my MFTDump.exe in this folder
3) Run MFTDUMP.exe against all the MFT files. You can do this in a batch file loop. 
Just be sure to name the output file because the default filename will overwrite the previous one.
-	E.g. Mftdump.exe –o hostname_mft.txt
-	You will now have a bunch of ?MFT.txt files in the folder.
-	Run mft2db against the folder
-	Mft2db.py dbname.db3 tmpRiffleLoad\MFT

If you want the Event Logs data loaded:
---------------------------------------
1) Traverse to the tmpRiffle\logs\evt folder.
2) Drop psloglist.exe in this folder (sysinternals utility)
3) Run psloglist.exe against all the evt files.
	Syntax:  psloglist -l <filename>.evt <log type> > <filename>.txt
        Note: if you are running Win7 you must convert the EVT file types to EVTX with
        this command:  wevtutil epl <filename>.evt <filename>.evtx /lf:true /ow:true

then use logparser 2.2 (from from Microsoft)

all logs:
----------
"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "Select * FROM <path>\*.evtx to exported.csv" -i:EVT -stats:off -msgErrorMode:NULL

logs (failed Logons):
---------------------
"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT ComputerName, EXTRACT_TOKEN (strings, 0, '|') AS UserName, Count(*) AS Failed_Logins FROM .\*.evtx WHERE EventID IN (529; 530; 531; 532; 533; 534; 535; 537; 539) GROUP by ComputerName, UserName ORDER by ComputerName, UserName, Failed_Logins DESC" to failedevtlogons.csv -i:EVT -stats:OFF -msgErrorMode:NULL 

"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT EXTRACT_TOKEN(strings, 6, '|') AS Domain, ComputerName, EXTRACT_TOKEN(strings, 5, '|') AS UserName, EXTRACT_TOKEN(strings, 13, '|') AS Source_Host, EXTRACT_TOKEN(strings, 19, '|') AS Source_IP, Count(*) AS #_Failed_Logins, EventID FROM <path>\*.evtx WHERE EventID IN (4625; 5461) GROUP by Domain, ComputerName, UserName, Source_Host, Source_IP, EventID ORDER by ComputerName, #_Failed_Logins DESC" to failedevtxlogons.csv -i:EVT -stats:off -msgErrorMode:NULL

Interactive logons:
-------------------
"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT Count(*) AS Logins, EXTRACT_TOKEN(strings, 1, '|') AS Domain, ComputerName, EXTRACT_TOKEN(strings, 0, '|') AS User, EXTRACT_TOKEN(strings, 13, '|') AS Source, EXTRACT_TOKEN(strings, 3, '|') AS Type, EventID FROM <path>\*.evtx  WHERE EventID = 528 AND Type = '10' Group by Domain, ComputerName, User, Source, Type, EventID ORDER BY Logins, Domain, User DESC" to interactiveevtlogons.csv  -i:EVT -stats:off -rtp:-1 -msgErrorMode:NULL

"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT Count(*) AS Logins, EXTRACT_TOKEN(strings, 1, '|') AS Domain, ComputerName, EXTRACT_TOKEN(strings, 0, '|') AS User, EXTRACT_TOKEN(strings, 18, '|') AS Source, EXTRACT_TOKEN(strings, 8, '|') AS Type, EventID FROM <path>\*.evtx WHERE EventID = 4624  AND Type = '10' Group by Domain, ComputerName, User, Source, Type, EventID ORDER BY Logins, Domain, User DESC" to interactiveevtxlogons.csv -i:EVT -stats:off -rtp:-1 -msgErrorMode:NULL

type 3, 8, 10 logins detailed
-----------------------------
"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT TO_STRING(TimeGenerated, 'yyyy-MM-dd hh:mm:ss' ) AS Time, EXTRACT_TOKEN(strings, 1, '|') AS Domain, ComputerName, EXTRACT_TOKEN(strings, 0, '|') AS UserName, EXTRACT_TOKEN(strings, 6, '|') AS Source_Host, EXTRACT_TOKEN(strings, 13, '|') AS Source_IP, EXTRACT_TOKEN(strings, 14, '|') AS Port, EXTRACT_TOKEN(strings, 3, '|') AS Type, EventID FROM *.evtx TO Remote_Logins.csv WHERE EventID IN (528; 540) AND Type IN ('3'; '10'; '8') Group by Domain, ComputerName, UserName, Time, Source_Host, Source_IP, Port, Type, EventID" -i:EVT -msgErrorMode:NULL

"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT TO_STRING(TimeGenerated, 'yyyy-MM-dd hh:mm:ss' ) AS Time, EXTRACT_TOKEN(strings, 2, '|') AS Domain, ComputerName, EXTRACT_TOKEN(strings, 5, '|') AS UserName, EXTRACT_TOKEN(strings, 13, '|') AS Source_Host, EXTRACT_TOKEN(strings, 19, '|') AS Source_IP, EXTRACT_TOKEN(strings, 20, '|') AS Port, EXTRACT_TOKEN(strings, 10, '|') AS Type, EventID FROM *.evtx TO Remote_Logins_2.csv WHERE EventID = 4625 AND Type IN ('3'; '10'; '8') Group by Domain, ComputerName, UserName, Time, Source_Host, Source_IP, Port, Type, EventID" -i:EVT -msgErrorMode:NULL

new acct creations
------------------
"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT TO_STRING(TimeGenerated, 'yyyy-MM-dd hh:mm:ss' ) AS Time, EXTRACT_TOKEN(strings, 0, '|') AS UserName, ComputerName, EXTRACT_TOKEN(strings, 3, '|') AS SID, EXTRACT_TOKEN(strings, 5, '|') AS Domain, EventID FROM *.evtx TO 4720_newaccount.csv WHERE EventID = 4720 ORDER by Time DESC" -i:EVT -msgErrorMode:NULL

"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" "SELECT TO_STRING(TimeGenerated, 'yyyy-MM-dd hh:mm:ss' ) AS Time, EXTRACT_TOKEN(strings, 0, '|') AS UserName, ComputerName, EXTRACT_TOKEN(strings, 3, '|') AS SID, EXTRACT_TOKEN(strings, 2, '|') AS Domain, EXTRACT_TOKEN(strings, 3, '|') AS Creator, EXTRACT_TOKEN(strings, 4, '|') AS CreatorDomain, EventID FROM *.evtx TO 624_newaccount.csv WHERE EventID = 624 ORDER by Time DESC" -i:EVT -msgErrorMode:NULL

app event query with powershell
-------------------------------
get-winevent -path <path> > appout.txt

 4) Load event logs with PY scripts

The following additional artifacts are collected but are not loaded to DB:
--------------------------------------------------------------------------
\network\hosts		HOSTS file
\network\ipconfig 	IPCONFIG -A
\ntuser			NTUSER.DAT Files
\index			Internet History (index.dat) files
\prefetch		Prefetch files (use PFDump.exe to create reports)
\Reg			Registry Hives
