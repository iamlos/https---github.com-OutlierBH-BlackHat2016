
' response Compromise Assessment
' Phase 1 "Diagnosis" Collection

' Copyright (c) 2013 - 2016 SSHOOK. All Rights Reserved Worldwide

' USAGE cscript risks.vbs <outpath> <hostname> <0|1 - autorunsc already ran>
' !!! SHANE - is this usage notation still accurate? I think hostname is auto-determined


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Main Code Block
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Option Explicit
Dim objShell: Set objShell = CreateObject("Wscript.shell")
Dim hostname: hostname = objshell.ExpandEnvironmentStrings("%computername%")
' dotnetAvailable is a global variable used by MD5
Dim dotnetAvailable: dotnetAvailable = DotNetTest
Dim sep : sep = ","
Dim FileAttrAlias : FileAttrAlias = 1024
Dim arrIgnoreSF : arrIgnoreSF = Array("AllUsersDesktop","AllUsersStartMenu","AllUsersPrograms","AllUsersStartup","Desktop","Favorites","Fonts","MyDocuments","NetHood","PrintHood","Recent","SendTo","StartMenu","Startup","Templates")
Dim arrIgnoreFolders : Set arrIgnoreFolders = CreateObject("Scripting.Dictionary")
Dim name
For Each name in arrIgnoreSF
    arrIgnoreFolders.Add LCase(objShell.SpecialFolders(name)), objShell.SpecialFolders(name)
Next

NetStat "netstat.csv", hostname
Processes "processes.csv", hostname
Autoruns "autoruns.csv", hostname
Startups "startups.csv", hostname
ScheduledTasks "scheduledtasks.csv", hostname
ListAllFiles "listfiles.csv", hostname
GetApplicationList "software.csv", hostname

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' ListAllFiles
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: filename - full path for the output csv file
'       hostname - name of host to write to csv file
'Description: This functions lists all files on the SystemRoot and 
'             UserProfile drives (if UserProfile is on a different drive)
'             and puts them into the specified csv file
' Remarks: A good discussion of "Permission Denied" errors in VBScript, even when running
'          as Admnistrator http://www.tek-tips.com/viewthread.cfm?qid=1643777
function ListAllFiles(filename, hostname)
    Dim sysDrive : sysDrive = Left(objshell.ExpandEnvironmentStrings("%systemroot%"), 3)
    Dim userDrive : userDrive = Left(objshell.ExpandEnvironmentStrings("%userprofile%"), 3)
    Dim objFileStream : Set objFileStream = CreateObject("Scripting.FileSystemObject")
    Dim objOut : Set objOut = objFileStream.CreateTextFile(filename)
    ListFiles objOut, filename, sysDrive, hostname
    If StrComp(sysdrive, userDrive, vbTextCompare) <> 0 then
        ListFiles objOut, filename, userDrive, hostname
    End If
End Function

Function isValidFolder(folder)
    If (folder.Attributes And FileAttrAlias) = FileAttrAlias then
        isValidFolder = false
    Else
        isValidFolder = true
    End If
    If isValidFolder then
        if arrIgnoreFolders.Exists(LCase(folder.Path)) Then
            isValidFolder = False
        End If
    End If   
End Function

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' ListFiles
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: objOut - CSV output file object
'       filename - full path for the output csv file
'       path - starting path for recursively listing files
'       hostname - name of host to write to csv file
'Description: This functions lists all files in the specified folder and all subfolders
'             and puts them into the specified csv file
function ListFiles(objOut, filename, path, hostname)
    Dim objFSO : Set objFSO = CreateObject("Scripting.FileSystemObject")
    Dim objFolder : Set objFolder = objFSO.GetFolder(path)
    Dim colFiles : Set colFiles = objFolder.Files
    Dim objFile
    For Each objFile in colFiles
        If isValidFolder(objFile) then
            WriteFile objOut, hostname, objFile
        End If
    Next
    ShowSubfolders objOut, hostname, objFolder

End Function


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' ShowSubFolders
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: objOut - output file object
'       hostname - name of host to write to csv file
'       Folder - starting folder
'Description: This subroutine lists all files in all subfolders
Sub ShowSubFolders(objOut, hostname, folder)
    Dim objFSO : Set objFSO = CreateObject("Scripting.FileSystemObject")
    Dim subFolder, objFile
    For Each subFolder in folder.SubFolders
        If isValidFolder(subFolder) then
            On Error Resume Next
            For Each objFile in subFolder.Files
                If Err.number = 0 then
                    WriteFile objOut, hostname, objFile
                End If
                On Error Resume Next
            Next
            ShowSubFolders objOut, hostname, subFolder
        End If
    Next
End Sub

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' WriteFile
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: objOut - output file object
'       hostname - name of host to write to csv file
'       objFile - file object
'Description: This subroutine outputs a line to the csv file with the
'             requested file information. 
'Remarks: Handy routines can be found at
'         https://msdn.microsoft.com/en-us/library/ebkhfaaz(v=vs.84).aspx
'         FileSystemObject Properties are at
'         https://msdn.microsoft.com/en-us/library/ea5ht6ax(v=vs.84).aspx 
Sub WriteFile(objOut, hostname, objFile)
    Dim s
    s = hostname & sep & qs(objFile.Path) & qs(objFile.Name)
    s = s & qs(objFile.Type)
    s = s & objFile.Size & sep
    s = s & objFile.DateCreated & sep
    s = s & objFile.DateLastModified & sep
    s = s & objFile.DateLastAccessed
    objOut.Writeline(s)
End Sub

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' NetStat
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: filepath - full path for the output csv file
'       hostname - name of host to write to csv file
'Description: This functions converts the output of "netstat -ano" into a csv file.
function NetStat(filepath, hostname)
    Dim objShell : Set objShell = CreateObject("Wscript.Shell")
    Dim objFileStream : Set objFileStream = CreateObject("Scripting.FileSystemObject")
    Dim objFile : Set objFile = objFileStream.CreateTextFile(filepath)
    Dim shExec : Set shExec = objShell.Exec("netstat -ano")
    Dim udpBound : udpBound = 3 '0 .. 3 is 4 columns  
    Dim maxBound : maxBound = udpBound + 1
    Dim regEx : Set regEx = New RegExp
    Dim line, str, cols
    regEx.Global = true
    regEx.IgnoreCase = True
    regEx.Pattern = "\s{2,}"

    Do While Not shExec.StdOut.AtEndOfStream  
        line = Trim(shExec.StdOut.ReadLine())
        line = regEx.Replace(line, sep)
        If ((line <> "") and (line <> "Active Connections")) and (line <> "Proto" + sep + "Local Address" + sep +"Foreign Address" + sep + "State" + sep + "PID") then
            cols = Split(line, sep)
            If UBound(cols) = udpBound then
                ReDim Preserve cols(maxBound)
                cols(maxBound) = cols(udpBound)
                cols(udpBound) = "" ' insert empty state value
            End If
            objFile.Writeline(hostname & sep & Columns(cols, maxBound))
        End If
    Loop  
End Function 

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Columns
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: values - array of values to list in columns
'       minimum - minimum number of columns to include
'Description: This functions converts the array of values to a delimited string,
'             ensuring there are at least <minimum> columns written
function Columns(values, minimum)
    Dim str : str = "" 
    If IsArray(values) then
        Dim count : count = UBound(values)
        If count < minimum then
            Dim difference : difference = minimum - count
            ReDim Preserve values(minimum)
            For i = count + 1 to UBound(values)
                values(i) = ""
            Next
        End if
        str = Join(values, sep)
    End If
    Columns = str
End Function


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Startups
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: filepath - full path for the output csv file
'       hostname - name of host to write to csv file
'Description: This functions drives everything for the startups collection, including
'             writing the output csv file. It hashes files in the startup directories
'             except when a file is a .lnk file. In those cases, the target of the link
'             is hashed.
Function Startups(filepath, hostname)
    Dim path, objFileStream, objFSO, objRootFolder, objShell
    Dim pathOne, pathTwo, file, newFile
    Set objFileStream = CreateObject("ADODB.Stream")
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objShell = CreateObject("Wscript.shell")
    objFileStream.CharSet = "utf-8"
    objFileStream.Open

    For Each path In GetUserPaths()
        pathOne = path + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        pathTwo = path + "\Start Menu\Programs\Startup"
        objRootFolder = ""
        If objFSO.FolderExists(pathOne) Then
            Set objRootFolder = objFSO.GetFolder(pathOne)
        ElseIf objFSO.FolderExists(pathTwo) Then
            Set objRootFolder = objFSO.GetFolder(pathTwo)
        End If
        If NOT objRootFolder="" Then
            For Each file In objRootFolder.Files
                If LCase(Right(file,4))=".lnk" Then
                    file = objShell.CreateShortcut(file).TargetPath
                    newFile = "lnk >> " + file
                Else
                    newFile = file
                End If
                objFileStream.WriteText hostname & sep & _
                                        qs(newFile) & _
                                        MD5(file) & vbCrLf
            Next
        End If
    Next

    pathOne = objshell.ExpandEnvironmentStrings("%systemdrive%") + _
              "\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    If objFSO.FolderExists(pathOne) Then
        Set objRootFolder = objFSO.GetFolder(pathOne)
        For Each file In objRootFolder.Files
            If LCase(Right(file,4))=".lnk" Then
                file = objShell.CreateShortcut(file).TargetPath
                newFile = "lnk >> " + file
            Else
                newFile = file
            End If
            objFileStream.WriteText hostname & sep & _
                                    qs(newFile) & _
                                    MD5(file) & vbCrLf
        Next
    End If

    objFileStream.SaveToFile filepath, 2
End Function


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Autoruns
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: filepath - full path for the output csv file
'       hostname - name of host to write to csv file
'Description: This functions drives everything for the runkey collection, including
'             writing the output csv file.
Function Autoruns(filepath, hostname)
    Dim path, values, value, quoteBlocks, quoteBlock
    Dim pathBlocks, pathBlock, strippedPath, paths
    Dim tempRunKeyNames, tempChildKeyNames, tempPaths
    Dim runKeyNames, childKeyNames, hashes, oReg
    Dim hkcuRunKeys, hklmRunKeys, hklmServiceKeys
    Dim key, newKey, hkcuKeys, hklmkeys, index
    Dim name, newName, names, i, j, userProfile, profiles
    Dim SYSTEM_ROOT, svchost1, svchost2, parts, sids
    Dim pathStart1, pathStart2, pathStart3, pathStart4
    Dim objFileStream, objshell, subKeyName, subKeyNames
    Dim profileName, profileNames, profileSID, profileSIDs
    Set objFileStream = CreateObject("ADODB.Stream")
    Set objshell = CreateObject("Wscript.shell")
    Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
    ReDim tempRunKeyNames(-1)
    ReDim tempChildKeynames(-1)
    ReDim tempPaths(-1)
    ReDim runKeyNames(-1)
    ReDim childKeynames(-1)
    ReDim paths(-1)
    Redim hashes(-1)
    Const HKEY_CURRENT_USER = &H80000001
    Const HKEY_LOCAL_MACHINE = &H80000002
    Const HKEY_USERS = &H80000003
    SYSTEM_ROOT = LCase(objshell.ExpandEnvironmentStrings("%windir%"))
    objFileStream.CharSet = "utf-8"
    objFileStream.Open
    hklmServiceKeys = Array("System\CurrentControlSet\Services", _
                            "System\ControlSet001\Services", _
                            "System\ControlSet002\Services")
    hklmRunKeys = Array("Software\Microsoft\Windows\CurrentVersion\Run", _
                        "Software\Microsoft\Windows\CurrentVersion\RunOnce", _
                        "Software\Microsoft\Windows\CurrentVersion\RunOnceEx", _
                        "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", _
                        "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", _
                        "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx", _
                        "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", _
                        "Software\Microsoft\Windows\CurrentVersion\RunServices", _
                        "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
    hkcuRunKeys = Array("Software\Microsoft\Windows\CurrentVersion\Run", _
                        "Software\Microsoft\Windows\CurrentVersion\RunOnce", _
                        "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", _
                        "Software\Microsoft\Windows\CurrentVersion\RunServices", _
                        "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")

    'HKLM\Software\Wow6432\Microsoft\Active Setup\Installed Components
    'HKLM\Software\Microsoft\Active Setup\Installed Components
    'Get this key
    '    Iterate through child keys
    '       Iterate through child values
    '	        If valueName = StubPath OR
    '           If valueName = LocalizedName OR
    '           If valueName = KeyFileName Then grab valueData
    '               If valueData starts with regsvr32.exe 

    'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
    'Get the ...\Windows key
    '    Iterate through child values
    '        If valueName = AppInit_DLLs then grab valueData
    '            pull paths from valueData

    'HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
    'Get this key
    '    Iterate through child keys
    '	    Iterate through child values
    '		    If valueName = DLLName Then grab valueData
    '			    If valueData is just a filename then look for it in system32

    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute  
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit 
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad 
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows 
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler  
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell 
    'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell 
    'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load 


    ' Get all the runkeys for users listed in the ProfileList key
    For Each path In GetUserPaths()
        objshell.Run "reg.exe load HKU\responseTemp " + path+"\ntuser.dat", 0, True
        parts = Split(path,"\")
        userProfile = parts(UBound(parts))
        For Each key In hkcuRunKeys
            Set hkcuKeys = GetRegKeyValues(HKEY_USERS, "responseTemp\" + key)
            names = hkcuKeys.Keys
            values = hkcuKeys.Items
            For i=0 To UBound(names)
                ReDim Preserve tempRunKeyNames(UBound(tempRunKeyNames)+1)
                ReDim Preserve tempChildKeyNames(UBound(tempChildKeyNames)+1)
                ReDim Preserve tempPaths(UBound(tempPaths)+1)
                tempRunKeyNames(UBound(tempRunKeyNames)) = "HKU\" + userProfile + "\" + _
                                                           Right(key,Len(key))
                tempChildKeyNames(UBound(tempChildKeyNames)) = names(i)
                tempPaths(UBound(tempPaths)) = values(i)
            Next
        Next
        objshell.Run "reg.exe unload HKU\responseTemp", 0, True
    Next

    ' Get all the runkeys for the users listed under HKEY_USERS
    Set profiles = GetSIDNameMappings()
    sids = profiles.Keys
    profileNames = profiles.Items
    oReg.EnumKey HKEY_USERS, "", subKeyNames
    For Each key In hkcuRunKeys
        For Each subKeyName In subKeyNames
            Set hkcuKeys = GetRegKeyValues(HKEY_USERS, subKeyName+"\"+key)
            names = hkcuKeys.Keys
            values = hkcuKeys.Items
            For i=0 To UBound(names)
                ReDim Preserve tempRunKeyNames(UBound(tempRunKeyNames)+1)
                ReDim Preserve tempChildKeyNames(UBound(tempChildKeyNames)+1)
                ReDim Preserve tempPaths(UBound(tempPaths)+1)
                For j=0 To UBound(sids)
                    If subKeyName = sids(j) Then
                        Exit For
                    End If
                Next
                tempRunKeyNames(UBound(tempRunKeyNames)) = "HKU\" + profileNames(j) + "\" + _
                                                           Right(key,Len(key))
                tempChildKeyNames(UBound(tempChildKeyNames)) = names(i)
                tempPaths(UBound(tempPaths)) = values(i)
            Next
        Next
    Next	

    ' Get all the runkeys for the current user
    For Each key In hkcuRunKeys
        Set hkcuKeys = GetRegKeyValues(HKEY_CURRENT_USER, key)
        names = hkcuKeys.Keys
        values = hkcuKeys.Items
        For i=0 To UBound(names)
            ReDim Preserve tempRunKeyNames(UBound(tempRunKeyNames)+1)
            ReDim Preserve tempChildKeyNames(UBound(tempChildKeyNames)+1)
            ReDim Preserve tempPaths(UBound(tempPaths)+1)
            tempRunKeyNames(UBound(tempRunKeyNames)) = "HKCU\" + userProfile + "\" + _
                                                       Right(key,Len(key))
            tempChildKeyNames(UBound(tempChildKeyNames)) = names(i)
            tempPaths(UBound(tempPaths)) = values(i)
        Next
    Next

    ' Get all the hklm runkeys	
    For Each key In hklmRunKeys
        Set hklmKeys = GetRegKeyValues(HKEY_LOCAL_MACHINE, key)
        names = hklmKeys.Keys
        values = hklmKeys.Items
        For i=0 To UBound(names)
            ReDim Preserve tempRunKeyNames(UBound(tempRunKeyNames)+1)
            ReDim Preserve tempChildKeyNames(UBound(tempChildKeyNames)+1)
            ReDim Preserve tempPaths(UBound(tempPaths)+1)
    	    tempRunKeyNames(UBound(tempRunKeyNames)) = "HKLM\" + key
            tempChildKeyNames(UBound(tempChildKeyNames)) = names(i)
            tempPaths(UBound(tempPaths)) = values(i)
        Next
    Next

    ' Get all service ImagePath and ServiceDll values
    pathStart1 = "\system32\"
    pathStart2 = "system32\"
    pathStart3 = "\systemroot\"
    pathStart4 = "systemroot\"
    svchost1 = objshell.ExpandEnvironmentStrings("%windir%") + "\system32\svchost.exe"
    svchost2 = chr(34) + svchost1 + chr(34)
    For Each key In hklmServiceKeys
        oReg.EnumKey HKEY_LOCAL_MACHINE, key, subKeyNames
        If Not IsNull(subKeyNames) then
            For Each subKeyName in subKeyNames
                Set hklmKeys = GetRegKeyValues(HKEY_LOCAL_MACHINE, key+"\"+subKeyName)
                names = hklmKeys.Keys
                values = hklmKeys.Items
                For i=0 To UBound(names)
                    If LCase(names(i))="imagepath" Then
                        If Left(LCase(values(i)),Len(pathStart1)) = pathStart1 Then
                            values(i) = SYSTEM_ROOT + "\" + values(i)
                        ElseIf Left(LCase(values(i)),Len(pathStart2)) = pathStart2 Then
                            values(i) = SYSTEM_ROOT + "\" + values(i)
                        ElseIf Left(LCase(values(i)),Len(pathStart3)) = pathStart3 Then
                            values(i) = SYSTEM_ROOT + "\" + Right(values(i),Len(values(i))-Len(pathStart3))
                        ElseIf Left(LCase(values(i)),Len(pathStart4)) = pathStart4 Then
                            values(i) = SYSTEM_ROOT + "\" + Right(values(i),Len(values(i))-Len(pathStart4))
                        End If
                        If Left(LCase(values(i)),Len(svchost1))=LCase(svchost1) OR _
                            Left(LCase(values(i)),Len(svchost2))=LCase(svchost2) Then
                            values(i) = GetRegKeyValue(HKEY_LOCAL_MACHINE, key+"\"+subKeyName+"\Parameters", "ServiceDll")
                            newKey = key+"\"+subKeyName+"\Parameters"
                            newName = "ServiceDll"
                        Else
                            newKey = key+"\"+subKeyName
                            newName = "ImagePath"
                        End If
                        ReDim Preserve tempRunKeyNames(UBound(tempRunKeyNames)+1)
                        ReDim Preserve tempChildKeyNames(UBound(tempChildKeyNames)+1)
                        ReDim Preserve tempPaths(UBound(tempPaths)+1)
                        tempRunKeyNames(UBound(tempRunKeyNames)) = "HKLM\" + newKey
                        tempChildKeyNames(UBound(tempChildKeyNames)) = newName
                        tempPaths(UBound(tempPaths)) = values(i)
                    End If
                Next
            Next
        End If
    Next

    For i=0 To UBound(tempPaths)
        quoteBlocks = CheckForRunDll(BreakUpByQuoteBlocks(tempPaths(i)))
        For Each quoteBlock In quoteBlocks
            pathBlocks = BreakUpByPathBlocks(quoteBlock)
            For Each pathBlock In pathBlocks
                strippedPath = GetPath(pathBlock)
                If NOT strippedPath = "" Then
                    ReDim Preserve runKeyNames(UBound(runKeyNames)+1)
                    ReDim Preserve childKeyNames(UBound(childKeyNames)+1)
                    ReDim Preserve paths(UBound(paths)+1)
                    runKeyNames(UBound(runKeyNames)) = tempRunKeyNames(i)
                    childKeyNames(UBound(childKeyNames)) = tempChildKeyNames(i)
                    paths(UBound(paths)) = strippedPath
                End If
            Next
        Next
    Next

    ' Calculate the MD5 sums and write the csv file
    For i=0 To UBound(paths)
        objFileStream.WriteText hostname & sep & _
                                qs(runKeyNames(i)) & _
                                qs(childKeyNames(i)) & _
                                qs(paths(i)) & _
                                MD5(paths(i)) & vbCrLf
    Next
    objFileStream.SaveToFile filepath, 2
End Function

'Output: An array of paths
'Description: This function first collects the list of user directory paths by iterating 
'             through the profilelist keys and grabbing the ProfileImagePath values. Any 
'             of those directories containing a ntuser.dat file is added to the output array.
Function GetUserPaths()
    Dim HKEY_LOCAL_MACHINE, key, values, hklmKeys, path, i
    Dim paths, subKeyNames, subKeyName
    Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
    Dim oReg: Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
    ReDim paths(-1)
    HKEY_LOCAL_MACHINE = &H80000002
    key = "Software\Microsoft\Windows NT\CurrentVersion\ProfileList"
    Set hklmKeys = GetRegKeyValues(HKEY_LOCAL_MACHINE, key)
    values = hklmKeys.Items

    For i=0 To UBound(values)
        If objFSO.FileExists(values(i) + "\ntuser.dat") Then
            ReDim Preserve paths(UBound(paths)+1)
            paths(UBound(paths)) = values(i)
        End If
    Next

    oReg.EnumKey HKEY_LOCAL_MACHINE, key, subKeyNames
    For Each subKeyName in subKeyNames
        path = GetRegKeyValue(HKEY_LOCAL_MACHINE, key+"\"+subKeyName, "ProfileImagePath")
        If objFSO.FileExists(path + "\ntuser.dat") Then
            ReDim Preserve paths(UBound(paths)+1)
            paths(UBound(paths)) = path
        End If
    Next

    GetUserPaths = paths
End Function

' Output: A dictionary
' Description: This function returns all the SID/ProfileName mappings.
Function GetSIDNameMappings()
    Dim HKEY_LOCAL_MACHINE, key, names, values, hklmKeys, path
    Dim subKeyNames, subKeyName
    Dim profiles: Set profiles = CreateObject("Scripting.Dictionary")
    Dim oReg: Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
    HKEY_LOCAL_MACHINE = &H80000002
    key = "Software\Microsoft\Windows NT\CurrentVersion\ProfileList"
    Set hklmKeys = GetRegKeyValues(HKEY_LOCAL_MACHINE, key)
    names = hklmKeys.Keys
    values = hklmKeys.Items

    oReg.EnumKey HKEY_LOCAL_MACHINE, key, subKeyNames
    For Each subKeyName in subKeyNames
        path = GetRegKeyValue(HKEY_LOCAL_MACHINE, key+"\"+subKeyName, "ProfileImagePath")
        profiles.Add subKeyName, Right(path,Len(path) - InStrRev(path,"\"))
    Next

    Set GetSIDNameMappings = profiles
End Function

' Input: hkey - root key value (i.e. HKEY_USERS, HKEY_LOCAL_HOST), this is a hex value
'        key - the key to extract values from
' Output: A dictionary containing the name/value pairs for all the children of 'key'
' Description: This function iterates through all the children keys of a specified root 
'              key. The child key values are retrieved and those name/value pairs are all
'              returned in a dictionary.
Function GetRegKeyValues(hkey, key)
    Dim oReg: Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
    Dim hkcuKeys: Set hkcuKeys = CreateObject("Scripting.Dictionary")
    Dim val, values, value, valueNames, valueTypes, i

    oReg.EnumValues hkey,key,valueNames,valueTypes
    If NOT IsNull(valueNames) Then
        For i=0 To UBound(valueNames)
            value = GetRegKeyValueWithType(valueNames(i),valueTypes(i),hkey,key)
            hkcuKeys.Add valueNames(i),value
        Next
    End If
    Set GetRegKeyValues = hkcuKeys
End Function

' Input: hkey - root key value (i.e. HKEY_USERS, HKEY_LOCAL_HOST), this is a hex value
'        key - the key to extract values from
'        valueName - the specific value name for which the value data should be returned
' Output: A string
' Description: This function iterates through all the children keys of a specified root 
'              key. The value for the 'valueName' value is returned.
Function GetRegKeyValue(hkey, key, valueName)
    Dim oReg: Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
    Dim val, values, value, valueNames, valueTypes, i
    oReg.EnumValues hkey,key,valueNames,valueTypes
    If NOT IsNull(valueNames) Then
        For i=0 To UBound(valueNames)
            If LCase(valueNames(i))=LCase(valueName) Then
                value = GetRegKeyValueWithType(valueNames(i),valueTypes(i),hkey,key)
                Exit For
            End If
        Next
    End If
    GetRegKeyValue = value
End Function

' Input: hkey - root key value (i.e. HKEY_USERS, HKEY_LOCAL_HOST), this is a hex value
'        key - the key for which the value is to be retrieved
'        valueName - the name of the value for which the value's data will be returned
'        valueType - the type of the value 
' Output: A string
' Description: This function retrieves the value data for the value name associated with 
'              the specified key.
Function GetRegKeyValueWithType(valueName,valueType,hkey,key)
    Dim oReg: Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
    Dim val, values, value
    Const REG_SZ = 1
    Const REG_EXPAND_SZ = 2
    Const REG_BINARY = 3
    Const REG_DWORD = 4
    Const REG_MULTI_SZ = 7

    Select Case valueType
        Case REG_SZ
            oReg.GetStringValue hkey,key,valueName,value
        Case REG_EXPAND_SZ
            oReg.GetExpandedStringValue hkey,key,valueName,value
        Case REG_BINARY
            oReg.GetBinaryValue hkey,key,valueName,values
            If NOT IsNull(values) Then
                value = ""
                For Each val In values
                    value = value + CStr(val) + " "
                Next
            End If
        Case REG_DWORD
            oReg.GetDWORDValue hkey,key,valueName,value
        Case REG_MULTI_SZ
            oReg.GetMultiStringValue hkey,key,valueName,values
            value = ""
            If NOT IsNull(values) Then
                For Each val In values
                    value = value + CStr(val) + " "
                Next
            End If
    End Select
    GetRegKeyValueWithType = value
End Function

' Input: inStr - A string
' Output: An array of strings
' Description: The original string is broken up into groups based on the double quotes
'              contained in the string. If there is only one double quote, the original 
'              string is returned in a single element array. Quotes are preserved.
Function BreakUpByQuoteBlocks(inStr)
    Dim quoteCount, block, blockStart, i, ch
    quoteCount = UBound(Split(inStr,chr(34)))
    Dim blocks
    ReDim blocks(-1)
    block = ""
    If quoteCount > 1 Then
        blockStart = False
        For i=1 To Len(inStr)
            ch = Mid(inStr,i,1)
            ' This is a double quote char
            If ch=chr(34) Then
                quoteCount = quoteCount - 1
                ' This is the end of a block
                If blockStart Then
                    block = block + ch
                    ReDim Preserve blocks(UBound(blocks)+1)
                    blocks(UBound(blocks)) = block
                    blockStart = False
                    block = ""
                ' This is the start of a block
                ElseIf quoteCount > 0 Then
                    If i=Len(inStr) Then
                        block = block + ch
                        ch = ""
                    End If
                    blockStart = True
                    If NOT block = "" Then
                        ReDim Preserve blocks(UBound(blocks)+1)
                        blocks(UBound(blocks)) = block
                    End If
                    block = ch
                ' This is the last quote
                Else
                    block = block + ch
                ' This is the middle of a block
                End If
            ' This is not a double quote char
            Else
                block = block + ch
            End If
        Next
        ' Add the remaining characters
        If NOT block = "" Then
            ReDim Preserve blocks(UBound(blocks)+1)
            blocks(UBound(blocks)) = block
        End If
    ' If there is 0 or 1 double quote
    Else
        ReDim Preserve blocks(0)
        blocks(0) = inStr
    End If
    BreakUpByQuoteBlocks = blocks
End Function

' Input: inArr - An array of strings
' Output: An array of strings
' Description: The original array, unless the first element is the path to rundll32.exe. 
'              In that case, the first element is dropped, the remaining elements are 
'              concatenated and then split by the comma char. Only the first element of 
'              'comma' array is returned (as a single element array). This is how rundll32
'              reg key data is parsed.
Function CheckForRunDll(inArr)
    Dim objshell: Set objshell = CreateObject("Wscript.shell")
    Dim theRest, fullName, shortName, i, match, firstQuoteGone
    fullName = LCase(objshell.ExpandEnvironmentStrings("%windir%") + "\system32\rundll32.exe")
    shortName = LCase(objshell.ExpandEnvironmentStrings("%windir%") + "\system32\rundll32")
    firstQuoteGone = inArr(0)
    If Left(firstQuoteGone,1)=chr(34) Then
        firstQuoteGone = Right(firstQuoteGone,Len(firstQuoteGone)-1)
    End If
    theRest = ""
    If LCase(Left(firstQuoteGone,Len(fullName)))=fullName Then
        theRest = Right(firstQuoteGone,Len(firstQuoteGone)-Len(fullName))
        match = True
    ElseIf LCase(Left(firstQuoteGone,Len(shortName)))=shortName Then
        theRest = Right(firstQuoteGone,Len(firstQuoteGone)-Len(shortName))
        match = True
    End If
    If match Then
        ' The rest of the string is the args for rundll32.exe
        For i=1 To UBound(inArr)
            theRest = theRest + inArr(i)
        Next
        ' If there are args
        If NOT theRest = "" Then
            CheckForRunDll = Array(Replace(Split(theRest,",")(0),chr(34),""))
        Else
            CheckForRunDll = inArr
        End If
    Else
        CheckForRunDll = inArr
    End If
End Function

' Input: inStr - A string
' Output: An array of strings
' Description: The original string is broken up into path groups. It is assumed that paths
'              start with '\\' or 'C:\' (where C could be any char). Each element of the 
'              output array should contain at most one path (possibly including flags, etc.).
Function BreakUpByPathBlocks(inStr)
    ' Split on ' \\' (add \\ back to front of pathname)
    Dim paths, sharePaths, i, j, drivePaths
    ReDim paths(-1)
    Dim trimmedDrivePath
    sharePaths = Split(inStr," \\")
    If Left(inStr,1)=chr(34) AND Right(inStr,1)=chr(34) Then
        BreakUpByPathBlocks = Array(inStr)
    Else
        For i=0 To UBound(sharePaths)
            If NOT sharePaths(i) = "" AND NOT sharePaths(i) = " " Then
                If i > 0 Then
                    sharePaths(i) = "\\" + sharePaths(i)
                End If
                ' For each string --> split on ':\' (add <drive letter>:\ back to front of pathname)
                drivePaths = Split(sharePaths(i),":\")
                If UBound(drivePaths) > 0 Then
                    For j=0 To UBound(drivePaths)
                        If NOT drivePaths(j) = "" AND NOT drivePaths(j) = " " Then
                            If j <> UBound(drivePaths) Then
                                drivePaths(j+1) = Right(drivePaths(j),1) + ":\" + drivePaths(j+1)
                                trimmedDrivePath = Left(drivePaths(j),Len(drivePaths(j))-1)
                            Else
                                trimmedDrivePath = drivePaths(j)
                            End If
                            If NOT trimmedDrivePath = "" AND NOT trimmedDrivePath = " " Then
                                ReDim Preserve paths(UBound(paths)+1)
                                paths(UBound(paths)) = trimmedDrivePath
                            End If
                        End If
                    Next
                Else
                    ReDim Preserve paths(UBound(paths)+1)
                    If Left(drivePaths(0),1) = " " Then
                        drivePaths(0) = Right(drivePaths(0),Len(drivePaths(0))-1)
                    End If
                    paths(UBound(paths)) = drivePaths(0)
                End If
            End If
        Next
        BreakUpByPathBlocks = paths	
    End If
End Function

' Input: inPath - a string containing a path and possibly some flags
' Output: existingPath - a substring of inPath which is a file that actually exists
' Description: This function finds a valid path in 'inPath' by splitting inPath by
'              spaces. It then starts at element 0 of the 'space array'. If that 
'              element is an actual file then that path is returned. If not, then 
'              it concatenates a space and the next array element and does the same
'              check. This process continues until a path mapping to an actual file 
'              is found or the array ends, in which case an empty string is returned.
Function GetPath(inPath)
    Dim splitPath, part, name, existingPath
    Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
    existingPath = ""
    inPath = Trim(inPath)
    If Left(inPath,1)=chr(34) AND Right(inPath,1)=chr(34) Then
        inPath = Mid(inPath,2,Len(inPath)-2)
        If objFSO.FileExists(inPath) Then
            existingPath = inPath
        End If
    Else
        name = ""
        splitPath = Split(inPath," ")
        For Each part In splitPath
            If name = "" Then
                name = part
            Else
                name = name + " " + part
            End If
            If objFSO.FileExists(name) Then
                existingPath = name
                Exit For
            End If
        Next
    End If
    GetPath = existingPath
End Function


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Running Processes WITH Loaded Modules
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: filepath - full path for the output csv file
'       hostname - name of host to write to csv file
'Description: This functions drives everything for the processes collection, 
'             including writing the output csv file. It calculates MD5s for all 
'             the processes that have modules loaded as well as for the loaded 
'             modules. Processes that do not have modules loaded are skipped. 
'             The API that enumerates the enumerates the modules skips the 
'             processes with no modules loaded and the API that enumerates all 
'             the processes does not include path information.
Function Processes(filepath, hostname)
    Dim objFileStream, objWMIProcess, objWMIService, processItems
    Dim specificFile, specificFiles, moduleItems, objFSO, objShell
    Dim SYSTEM_ROOT, pathStart1, pathStart2, hash
    Set objShell = CreateObject("Wscript.shell")
    Set objFileStream = CreateObject("ADODB.Stream")
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    objFileStream.CharSet = "utf-8"
    objFileStream.Open

    ' Get process list for the local host
    Set objWMIProcess = GetObject("winmgmts:\\localhost\root\cimv2")
    Set processItems = objWMIProcess.ExecQuery("Select * From Win32_Process",,16)
    Set objWMIService = GetObject("winmgmts:\\localhost\root\cimv2")
    Set moduleItems = objWMIService.ExecQuery("Select * from Win32_PerfFormattedData_PerfProc_FullImage_Costly",,16)

    Dim procArr()
    ReDim procArr(processItems.Count-1,2)
    '0: process name
    '1: process id
    Dim moduleArr()
    ReDim moduleArr(moduleItems.Count-1,3)
    '0: parent process name
    '1: module path
    '2: MD5
    '3: pid list
    Dim processItem, moduleItem, i, j
    SYSTEM_ROOT = LCase(objShell.ExpandEnvironmentStrings("%windir%"))
    pathStart1 = "\systemroot\"
    pathStart2 = "systemroot\"

    i = 0
    For Each processItem in processItems
        procArr(i,0) = processItem.Name
        procArr(i,1) = Cstr(processItem.ProcessID)
        i = i + 1
    Next

    i = 0
    For Each moduleItem In moduleItems
        Dim parts, pids, index, name, path
        parts = Split(moduleItem.Name,"/")
        moduleArr(i,0) = LCase(parts(0))

        If Left(LCase(parts(1)),Len(pathStart1)) = pathStart1 Then
            parts(1) = SYSTEM_ROOT + "\" + Right(parts(1),Len(parts(1))-Len(pathStart1))
        ElseIf Left(LCase(parts(1)),Len(pathStart2)) = pathStart2 Then
            parts(1) = SYSTEM_ROOT + "\" + Right(parts(1),Len(parts(1))-Len(pathStart2))
        End If

        index = InStrRev(parts(1),"#")
        If index = 0 Then
            moduleArr(i,1) = parts(1)
        Else
            moduleArr(i,1) = Left(parts(1), index-1)
        End If

        ' Save the MD5
        moduleArr(i,2) = MD5(moduleArr(i,1))

        pids = ""
        For j=0 To UBound(procArr)
            index = InStrRev(procArr(j,0),".")
            If index = 0 Then
                If LCase(procArr(j,0)) = LCase(parts(0)) Then
                    pids = pids + " " + procArr(j,1)
                End If
            Else
                name = Left(procArr(j,0), index)
                If LCase(name) = LCase(parts(0))+"." Then
                    If pids = "" Then
                        pids = procArr(j,1)
                    Else
                        pids = pids + " " + procArr(j,1)
                    End If
                End If
            End If
        Next
        moduleArr(i,3) = pids
        i = i + 1
    Next

    ' Calculate the MD5s and write to the csv file	
    For i=0 To UBound(moduleArr)
        objFileStream.WriteText hostname & sep & _
                                qs(moduleArr(i,0)) & _
                                qs(moduleArr(i,1)) & _
                                qs(moduleArr(i,2)) & _
                                q(moduleArr(i,3)) & vbCrLf
    Next
    objFileStream.SaveToFile filepath, 2
End Function

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Scheduled Tasks and AT Jobs
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: filepath - full path for the output csv file
'       hostname - name of host to write to csv file
'       schtasksFile - path to the text file containing the output of the schtasks.exe cmd
'Description: This functions drives everything for the scheduled tasks collection, including
'             writing the output csv file. This is a port of a portion of the response.py
'             schtasks parser which collects just the 'Task To Run' entry and parses it for 
'             paths to files to hash. This function handles English and Spanish.
Function ScheduledTasks(filepath, hostname)
    Dim HostNameEn, HostNameEs, TaskNameEn, TaskNameEs
    Dim TaskToRunEn, TaskToRunEs, File, row, rows
    Dim headerParsed, record, record_start, i, taskname
    Dim fields, TaskNameIndex, TaskToRunIndex, taskToRun
    Dim quoteBlocks, quoteBlock, pathBlocks, pathBlock, strippedPath
    Dim objShell: Set objShell = CreateObject("Wscript.shell")
    Dim objFileStream: Set objFileStream = CreateObject("ADODB.Stream")
    Dim schtasksFile: schtasksFile = "schtasks_tmp.txt"
    Dim cmdRet: Set cmdRet = objShell.exec("schtasks /query /v /fo csv")
    Dim lines: lines = cmdRet.StdOut.ReadAll()
    If Len(lines) < 1 Then
	    Exit Function
    End If
    objFileStream.CharSet = "utf-8"
    objFileStream.Open

    ' Keywords for English and Spanish field identification
    HostNameEn = chr(34) + "HostName" + chr(34)
    HostNameEs = chr(34) + "Nombre de host" + chr(34)
    TaskNameEn = "TaskName"
    TaskNameEs = "Nombre de tarea"
    TaskToRunEn = "Task To Run"
    TaskToRunEs = "Tarea que se ejecutar"

    rows = Split(lines,vbNewLine)

    headerParsed = False
    record = ""
    record_start = False

    For Each row In rows
        row = Trim(row)
        If row <> "" Then
            ' Parse the header and identify the indexes for the fields we want
            If NOT headerParsed Then
                If Left(row,Len(HostNameEn)) = HostNameEn OR _
                   Left(row,Len(HostNameEs)) = HostNameEs Then
                    fields = Split(row,chr(34)+","+chr(34))
                    For i=0 To UBound(fields)
                        If fields(i) = TaskNameEn OR fields(i) = TaskNameEs Then
                            TaskNameIndex = i
                        ElseIf fields(i) = TaskToRunEn OR fields(i) = TaskToRunEs Then
                            TaskToRunIndex = i
                        End If
                    Next
                    headerParsed = True
                End If
            Else
                ' If row starts with the host's name
                If Left(row,Len(chr(34)+hostname+chr(34))) = chr(34)+hostname+chr(34) Then
                    If record_start Then
                        record = Replace(record,vbTab,"")
                        fields = Split(record,chr(34)+","+chr(34))
                        taskname = Replace(fields(TaskNameIndex),"\","/")
                        taskToRun = fields(TaskToRunIndex)
                        quoteBlocks = CheckForRunDll(BreakUpByQuoteBlocks(ExpandEnvironmentVars(taskToRun)))
                        For Each quoteBlock In quoteBlocks
                            pathBlocks = BreakUpByPathBlocks(quoteBlock)
                            For Each pathBlock In pathBlocks
                                strippedPath = GetPath(pathBlock)
                                If NOT strippedPath = "" Then
                                    objFileStream.WriteText hostname & sep & _
                                                            qs(taskname) & _
                                                            qs(strippedPath) & _
                                                            MD5(strippedPath) & vbCrLf
                                End If
                            Next
                        Next
                        record = ""
                    Else
                        record_start = True
                    End If
                End If
                '# skip all the header lines
                If NOT Left(row,Len(HostNameEn)) = HostNameEn AND _
                   NOT Left(row,Len(HostNameEs)) = HostNameEs Then
                    ' This is how I handle records with newline chars embedded
                    If record_start Then
                        record = record + row + " "
                    End If
                End If
            End If
        End If
    Next
    ' Grab the last record
    If record <> "" Then
        record = Replace(record,vbTab,"")
        fields = Split(record,chr(34)+","+chr(34))
        taskname = Replace(fields(TaskNameIndex),"\","/")
        taskToRun = fields(TaskToRunIndex)
        quoteBlocks = CheckForRunDll(BreakUpByQuoteBlocks(ExpandEnvironmentVars(taskToRun)))
        For Each quoteBlock In quoteBlocks
            pathBlocks = BreakUpByPathBlocks(quoteBlock)
            For Each pathBlock In pathBlocks
                strippedPath = GetPath(pathBlock)
                If NOT strippedPath = "" Then
                    objFileStream.WriteText hostname & sep & _
                                            qs(taskname) & _
                                            qs(strippedPath) &  _
                                            MD5(strippedPath) & vbCrLf
                End If
            Next
        Next
    End If
    objFileStream.SaveToFile filepath, 2
End Function

' Input: inStr - string
' Description: This function uses a regex to parse the input string looking for environment 
'              variables. The function attempts to expand any environment variable pattern 
'              found in the string. If the expansion is successful, the variable is replaced.
'              This isn't full-proof. If environment varialbe patterns (i.e. %windir%) are legal 
'              file names so I suppose it's possible for there to be a legitimate file containing 
'              that pattern.
Function ExpandEnvironmentVars(inStr)
    Dim match, matches, base
    Dim objShell: Set objShell = CreateObject("Wscript.Shell")
    Dim regex: Set regex = New RegExp
    regex.Global = True
    regex.Pattern = "%[A-Za-z]+%\\"
    Set matches = regex.Execute(inStr)
    For Each match in matches
        base = Left(match.Value,Len(match.Value)-1)
        inStr = Replace(inStr, match.Value, objshell.ExpandEnvironmentStrings(base) + "\")
    Next
    ExpandEnvironmentVars = inStr
End Function

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Hashing Algorithms
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

' If filename exists then
'   If dotnet is available then
'       Calculate MD5 with .NET
'   Else if fciv.exe is in the current working directory then
'     Calculate MD5 with fciv
'   Else return "" as the MD5 
Function MD5(filename)
    Dim hash
    Dim objFSO : Set objFSO = CreateObject("Scripting.FileSystemObject")
    If objFSO.FileExists(filename) Then
        If dotNetAvailable Then
            MD5 = DotNetMD5(filename)
        ElseIf objFSO.FileExists("fciv.exe") Then
            MD5 = FcivMD5(filename)
        Else
            MD5 = ""
        End If
    Else
        MD5 = ""
    End If
End Function

' MD5 Hashing via fciv.exe
' Requires fciv.exe in the same directory
' Assumption that the file exists
' Expects successful fciv output to be as follows:
' //
' // File Checksum Integrity Verifier version 2.05.
' //
' MD5 filename
' Expects failed fciv output to be more than four lines
Function FcivMD5(strPath)
    Dim goWSH : Set goWSH = CreateObject( "WScript.Shell" ) 
    Dim cmdRet: Set cmdRet = goWSH.exec("fciv.exe " + strPath)
    Dim cmdOutput, lines
    cmdOutput = cmdRet.StdOut.ReadAll()
    lines = Split(cmdOutput,chr(10))
    If UBound(lines) > 4 Then
        FcivMD5 = ""
    Else
        FcivMD5 = Split(lines(3)," ")(0)
    End If
End Function

' MD5 Hashing via .NET
' Requires > .NET 1.1
' Assumption that the file exists
Function DotNetMD5(strPath)
    On Error Resume Next
    Dim BinaryStream, ReadBinaryFile
    Dim bytes
    Dim strIn, strOut, pos
    Const adTypeBinary = 1

    ' ADODB and MD5 crypto objects from .NET 1.1 + 
    Set DotNetMD5 = CreateObject("System.Security.Cryptography.MD5CryptoServiceProvider")
    If Err.Number <> 0 Then
        Err.Clear
        DotNetMD5 = ""
        Exit Function
    End If

    ' ADODB Stream Method
    Set BinaryStream = CreateObject("ADODB.Stream")
    If Err.Number <> 0 Then
        Err.Clear
        DotNetMD5 = ""
        Exit Function
    End If

    ' Get binary stream type
    BinaryStream.Type = adTypeBinary
    If Err.Number <> 0 Then
        Err.Clear
        DotNetMD5 = ""
        Exit Function
    End If

    ' open stream
    BinaryStream.Open
    If Err.Number <> 0 Then
        Err.Clear
        DotNetMD5 = ""
        Exit Function
    End If

    ' Load file from disk to stream
    BinaryStream.LoadFromFile strPath
    If Err.Number <> 0 Then
        Err.Clear
        DotNetMD5 = ""
        Exit Function
    End If

    ' Open stream and get binary data
    ReadBinaryFile = BinaryStream.Read
    If Err.Number <> 0 Then
        Err.Clear
        DotNetMD5 = ""
        Exit Function
    End If

    ' Calculate hash
    bytes = DotNetMD5.ComputeHash_2((ReadBinaryFile))
    If Err.Number <> 0 Then
        Err.Clear
        DotNetMD5 = ""
        Exit Function
    End If

    ' Convert the byte array back to a hex string
    strOut = ""
    For pos = 1 To Lenb(bytes)
        strOut = strOut & LCase(Right("0" & Hex(Ascb(Midb(bytes, pos, 1))), 2))
    Next

    DotNetMD5 = strOut
End Function

' Return True if the .NET MD5 hashing library is available. Return False otherwise.
Function DotNetTest()
    Dim outFile, md5Lib
    outFile = "responseDotNetTest.vbs"
    md5Lib = chr(34) + "System.Security.Cryptography.MD5CryptoServiceProvider" + chr(34)
    Dim objShell: Set objShell = CreateObject("WScript.Shell")
    Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
    Dim objFile: Set objFile = objFSO.CreateTextFile(outFile, True)
    objFile.Write("On Error Resume Next" + vbCrLf)
    objFile.Write("Err.Clear" + vbCrLf)
    objFile.Write("Dim obj: Set obj = CreateObject(" + md5Lib + ")" + vbCrLf)
    objFile.Write("If Err.Number <> 0 Then" + vbCrLf)
    objFile.Write(sep + "Err.Clear" + vbCrLf)
    objFile.Write(sep + "On Error Goto 0" + vbCrLf)
    objFile.Write(sep + "wscript.Quit 0" + vbCrLf)
    objFile.Write("Else" + vbCrLf)
    objFile.Write(sep + "wscript.Quit 1" + vbCrLf)
    objFile.Write("End If")
    objFile.Close
    Dim objExec: Set objExec = objShell.Exec("cscript " + outFile)
    wscript.sleep(3000)
    If objExec.ExitCode = 0 Then
        DotNetTest = False
    Else
        DotNetTest = True
    End If
    objExec.Terminate()	
    objFSO.DeleteFile(outFile)
End Function

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' Collection of Installed Software Details
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

' This functions sets up the output file and calls the functions that actually
' collect the information about installed software
Function GetApplicationList(filepath, hostname)
    Dim objShell: Set objShell = CreateObject("WScript.Shell")
    Dim programFiles: programFiles = objShell.ExpandEnvironmentStrings("%ProgramFiles%")
    Dim programFilesX86: programFilesX86 = objShell.ExpandEnvironmentStrings("%ProgramFiles(x86)%")
    Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
    Dim objFileStream: Set objFileStream = CreateObject("ADODB.Stream")
    objFileStream.CharSet = "utf-8"
    objFileStream.Open

    If programFiles <> "%ProgramFiles%" and objFSO.FolderExists(programFiles) Then
        WriteMetadata programFiles, objFileStream, hostname
    End If
    If programFilesX86 <> "%ProgramFiles(x86)%" and objFSO.FolderExists(programFilesX86) Then
        WriteMetadata programFilesX86, objFileStream, hostname
    End If

	GetInstalledFromAPI objFileStream, hostname
	
    ' Write the data out to file
    objFileStream.SaveToFile filepath, 2
End Function


' This function takes a root path as input and recursively checks files against 
' a prescribed list of file types. If a file matches one of those file types then this 
' function writes metadata about that file to an output file. This function doesn't 
' return anything.
Function WriteMetadata(path, fileStream, hostname)
    Dim objShell: Set objShell = CreateObject("Shell.Application")
    Dim objFolder: Set objFolder = objShell.Namespace(path)
	Dim strFileName, folder, company, creationDate
	' Write metadata for files of the relevant file type.
	If NOT objFolder Is Nothing Then
        For Each strFileName In objFolder.Items
            If IsRelevantType(strFileName.Path) Then
                fileStream.WriteText(hostname & sep) ' hostname
                fileStream.WriteText(qs(objFolder.GetDetailsOf(strFileName, 0))) ' filename
				fileStream.WriteText(objFolder.GetDetailsOf(strFileName, 4) & sep) ' created date
				fileStream.WriteText(qs(objFolder.GetDetailsOf(strFileName, 25))) ' copyright
                fileStream.WriteText(qs(objFolder.GetDetailsOf(strFileName, 33))) ' company name
				fileStream.WriteText(qs(objFolder.GetDetailsOf(strFileName, 34)))' description
				fileStream.WriteText(qs(objFolder.GetDetailsOf(strFileName, 156))) ' file version
                fileStream.WriteText(qs(objFolder.GetDetailsOf(strFileName, 177))) ' path
				fileStream.WriteText(qs(objFolder.GetDetailsOf(strFileName, 270))) ' product name
				fileStream.WriteText(q(objFolder.GetDetailsOf(strFileName, 271)) & vbCrLf) ' product version
            End If
        Next
    End If

    ' Go through subfolders
    Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
	On Error Resume Next
    For Each folder in objFSO.GetFolder(path).SubFolders
        If Err.Number <> 0 Then
            Err.Clear
            Exit For
        End If
        WriteMetadata folder.path, fileStream, hostname
    Next
	On Error Goto 0
End Function


' This function takes a filename as input and returns True if the file has one of the 
' extensions in the 'extensions' array, and returns False otherwise.
Function IsRelevantType(filename)
    Dim ext, extension
    Dim extensions: extensions = Array("exe")
    Dim dotIndex: dotIndex = InStrRev(filename, ".")
    IsRelevantType = False
    If dotIndex > 0 Then
        ext = Right(filename,Len(filename)-dotIndex)
        For Each extension In extensions
            If ext = extension Then
                IsRelevantType = True
                Exit For
            End If
        Next
    End If
End Function


' This function collects application information from the WMI Win32_Product API.
Function GetInstalledFromAPI(fileStream, hostname)
    Dim objWMI: Set objWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
    Dim software: Set software = objWMI.ExecQuery("SELECT * FROM Win32_Product")
	Dim objSoftware
    For Each objSoftware in software
        fileStream.WriteText(hostname & sep) ' hostname
        fileStream.WriteText(qs(objSoftware.PackageName)) ' filename
        fileStream.WriteText(objSoftware.InstallDate & sep) ' created date
        fileStream.WriteText("" & sep) ' copyright
        fileStream.WriteText(qs(objSoftware.Vendor)) ' company name
        fileStream.WriteText(qs(objSoftware.Description)) ' description
        fileStream.WriteText("" & sep) ' file version
        fileStream.WriteText(qs(objSoftware.InstallLocation)) ' path
        fileStream.WriteText(qs(objSoftware.Name)) ' product name
        fileStream.WriteText(q(objSoftware.Version) & vbCrLf) ' product version
    Next
End Function

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' q
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: value - value to quote
'Description: Puts quotes around the value
Function q(value)
    q = chr(34) & value & chr(34)
End Function

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'
' qs
'
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'Input: value - value to quote
'Description: Puts quotes around the value and adds sep to the end
Function qs(value)
    qs = q(value) & sep    
End Function