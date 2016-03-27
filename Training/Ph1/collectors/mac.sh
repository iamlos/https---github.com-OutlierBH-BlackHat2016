#!/bin/bash

# usage: sudo sh presponse.sh

# set environment variables, traget diretory, and config settings

# basename of results archive
IRCASE=`hostname`
# output destination, change according to needs
LOC=/tmp/$IRCASE
# tmp file to redirect results
TMP=$LOC/$IRCASE'_tmp.txt'
# redirect stderr
ERROR_LOG=$LOC/'errors.log'

# make target directories for results
mkdir $LOC 
touch $ERROR_LOG 
mkdir $LOC/userprofiles
mkdir $LOC/startupitems
mkdir $LOC/launchd
mkdir $LOC/launchd/library_launchdaemons
mkdir $LOC/launchd/system_library_launchdaemons
mkdir $LOC/launchd/system_library_launchagents

# collect Phase 1 data
function collect {

    # kernel extensions
    kextstat | sed 1d > $TMP
    while read Index Refs Address Size Wired Name Version Link
    do
        echo -e "$Index\t$Name\t$Version\t$Size\t$Link" >> $LOC/$IRCASE'_mac-modules.txt'
        kextfind -no-paths -b $Name -print-dependencies >> $LOC/$IRCASE'_mac-modules.txt'
        echo "" >> $LOC/$IRCASE'_mac-modules.txt'
    done < $TMP
    rm $TMP

    # operating system details
    uname -s > $LOC/$IRCASE'_mac-version.txt'
    uname -n >> $LOC/$IRCASE'_mac-version.txt'
    uname -r >> $LOC/$IRCASE'_mac-version.txt'
    uname -v >> $LOC/$IRCASE'_mac-version.txt'
    uname -m >> $LOC/$IRCASE'_mac-version.txt'
    uname -p >> $LOC/$IRCASE'_mac-version.txt'

    # network interfaces
    ifconfig -a > $LOC/$IRCASE'_mac-ifconfig.txt'

    # list of files
    {
        # common OSX locations to exlcude (e.g. backups, index, etc)
        EXCLUDES="-path /Volumes -o -path /.Spotlight-V100 -o -path /Network -o -path /.MobileBackups"

        # find with exclusions
        find -x / \( $EXCLUDES \) -prune -o -type f -exec ls -dilsT {} \;

        # resurusive ls 
        # ls -AlRtT /

    } > $LOC/$IRCASE'_mac-ls.txt'

    # users and groups (used when running in single mode only)
    cp /etc/passwd $LOC/$IRCASE'_mac-passwd.txt'
    cp /etc/group $LOC/$IRCASE'_mac-group.txt'

    # running processes
    ps aeSxww > $LOC/$IRCASE'_mac-ps.txt'

    # network status
    netstat -van > $LOC/$IRCASE'_mac-netstat.txt'

    # system messages (for kern debug and stuff see syslog)
    dmesg > $LOC/$IRCASE'_mac-dmesg.txt'

    # list of open files
    lsof +L > $LOC/$IRCASE'_mac-lsof-linkcounts.txt'
    lsof -i > $LOC/$IRCASE'_mac-lsof-netfiles.txt'

    # list of services
    launchctl list > $LOC/$IRCASE'_mac-launchctl.txt'

    # system hardware and configuration
    system_profiler > $LOC/$IRCASE'_mac-system_profiler.txt'

    # crontab
    for user in $(dscl . -list /Users)
    do
         (echo $user
          crontab -u $user -l
          echo " ") >> $LOC/$IRCASE'_mac-crontab-users.txt'
    done

    cp /usr/lib/cron/cron.allow $LOC/$IRCASE'_mac-cronallow.txt'
    cp /etc/crontab $LOC/$IRCASE'_mac-crontab.txt'

    # connections attemps (previous to Mountain Lion. For 10.8 see syslog)
    cp /var/log/secure.log $LOC/$IRCASE'_mac-securelog.txt'

    # last logins
    last > $LOC/$IRCASE'_mac-last.txt'

    date '+%Y-%m-%d %H:%M:%S %Z' > $LOC/$IRCASE'_mac-date.txt'

    locale > $LOC/$IRCASE'_mac-locale.txt'

    # directory service
    dscacheutil -q service > $LOC/$IRCASE'_mac-dsservice.txt'
    dscacheutil -q group > $LOC/$IRCASE'_mac-dsgroup.txt'

    # syslog
    syslog > $LOC/$IRCASE'_mac-syslog.txt'

    # startup items
    for d in /Library/StartupItems/*
    do
        cp -r $d /$LOC/startupitems
    done

    # /Library/LaunchDaemons
    for f in /Library/LaunchDaemons/*
    do
        cp $f $LOC/launchd/library_launchdaemons
    done

    # /System/Library/LaunchDaemons
    for f in /System/Library/LaunchDaemons/*
    do
        cp $f $LOC/launchd/system_library_launchdaemons
    done

    # /System/Library/LaunchAgents
    for f in /System/Library/LaunchAgents/*
    do
        cp $f $LOC/launchd/system_library_launchagents
    done

    #
    # Userprofile Propagation
    #

    # user list
    dscacheutil -q user > $LOC/$IRCASE'_mac-userlist.txt'

    for u in /Users/*/
    do
        # set up user directory
        mkdir $LOC/userprofiles/$user
        user=`echo $u | cut -d'/' -f3`
        mkdir $LOC/userprofiles/$user
        mkdir $LOC/userprofiles/$user/launchagents

        # ssh known hosts
        cp /Users/$user/.ssh/known_hosts $LOC/userprofiles/$user

        # bash history
        cat /Users/$user/.*_history > $LOC/userprofiles/$user/shell_history.txt

        # keychains
        cat /Users/$user/Library/Keychains/*.keychain > $LOC/userprofiles/$user/keychains.bin

        # user launchagents
        for la in /Users/$user/Library/LaunchAgents/*
        do 
            cp $la $LOC/userprofiles/$user/launchagents
        done

        # recent items
        cp /Users/$user/Library/Preferences/com.apple.recentitems.plist $LOC/userprofiles/$user
        # convert binary plist data into xml format for use in parsing
        #plutil -convert xml1 $LOC/userprofiles/$user
    done


    #
    # Build and Application Inconsistencies
    #

    # system information
    cp /System/Library/CoreServices/SystemVersion.plist $LOC/system_version.plist
    # java version
    java –version 2>&1 | tee $LOC/$IRCASE'_java_version.txt'
    # flash player 
    cp /Library/Internet\ Plug-Ins/Flash\ Player.plugin/Contents/version.plist $LOC/flash.plist
    # java applet 
    cp /Library/Internet\ Plug-Ins/JavaAppletPlugin.plugin/Contents/Info.plist $LOC/java.plist
    # firefox 
    cp /Applications/Firefox.app/Contents/Info.plist $LOC/firefox.plist
    # chrome 
    cp /Applications/Google\ Chrome.app/Contents/Info.plist $LOC/chrome.plist
    # safari 
    cp /Applications/Safari.app/Contents/version.plist $LOC/safari.plist
}

# run collect and catch errors
ERRORS=$(collect 2>&1)

# log errors
echo "$ERRORS" > $ERROR_LOG

# create zip file and clean up
cd $LOC
zip -9r /tmp/$IRCASE'.zip' * > /dev/null
cd /tmp
rm -r $LOC

