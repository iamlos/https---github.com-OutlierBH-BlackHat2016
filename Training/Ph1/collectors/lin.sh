#!/bin/bash

# usage: sudo bash presponse.sh <sleep time>
# <sleep time> is a floating point number that will be used 
# to slow down the running of the 'ls' command

#
# set environment variables, traget diretory, and config settings
#

# basename of results archive
IRCASE=`hostname`
# output destination, change according to needs
LOC=/tmp/$IRCASE
# tmp file to redirect results
TMP=$LOC/$IRCASE'_tmp.txt'
# redirect stderr
ERROR_LOG=$LOC/'errors.log'

# This sleep stuff is for the ls command. If a sleep value is 
# provided then the script will sleep between each 'get' of the 
# file listing (actually done by 'find').
if [ $# == 1 ]
then
    SLEEP=$1
else
    SLEEP=0
fi

{
    mkdir $LOC
    touch $ERROR_LOG 
    mkdir $LOC/userprofiles
} 2> /dev/null


#
# collect data for Phase 1 analysis
#

function collect {

    # current datetime
    date '+%Y-%m-%d %H:%M:%S %Z %:z' > $LOC/'date.txt'

    # running processes
    {
        PS_FORMAT=user,pid,ppid,vsz,rss,tname,stat,stime,time,args

        if ps axwwSo $PS_FORMAT &> /dev/null
        then
            # bsd
            ps axwwSo $PS_FORMAT
        elif ps -eF &> /dev/null
        then
            # gnu
            ps -eF
        else
            # bsd without ppid
            ps axuSww 
        fi
    } > $LOC/'ps.txt'

    # active network connections
    {
        if netstat -pvWanoee &> /dev/null
        then
            # gnu
            netstat -pvWanoee
        else
            # redhat/centos
            netstat -pvTanoee
        fi
    } > $LOC/'netstat.txt'

    # list of open files
    if [ -x /sbin/lsof ]
    then 
        # rhel5
        LSOF=/sbin/lsof
    else
        LSOF=`which lsof`
    fi
    # list of open files, link counts
    $LSOF +L > $LOC/'lsof-linkcounts.txt'
    # list of open files, with network connection
    $LSOF -i > $LOC/'lsof-netfiles.txt'

    # list all services and runlevel
    if chkconfig -l &> /dev/null
    then
        chkconfig -l > $LOC/'chkconfig.txt'
    else
        chkconfig --list > $LOC/'chkconfig.txt'
    fi

    # cron
    # users with crontab access
    cp /etc/cron.allow $LOC/'cronallow.txt'
    # users with crontab access
    cp /etc/cron.deny $LOC/'crondeny.txt'
    # crontab listing
    cp /etc/crontab $LOC/'crontab.txt'
    # cronfile listing
    ls -al /etc/cron.* > $LOC/'cronfiles.txt'


    # directory listings
    # The listings are actually done through the 'find' command, not the ls command.
    # The '-xdev' flag prevents from from walking directories on other file systems.
    # If the user provides a floating point number as the first argument to this script
    #  it will be used as the sleep value for pausing between reading the next line in 
    #  the find command. This results in a lot less CPU usage, but the script can take 
    #  a lot longer.
    IFS=$'\n';
    for line in $(find / -xdev \( -path /var/cache -o -path /var/spool \) -prune -o -type f -printf '%C+\t%CZ\t' -ls);
        do
            if [ $SLEEP != 0 ]
            then
                sleep $SLEEP
            fi
            echo "$line" >> $LOC/'ls.txt';
    done


    # network interfaces
    if [ -x /sbin/ifconfig ]
    then 
        # rhel5
        IFCONFIG=/sbin/ifconfig
    else
        IFCONFIG=`which ifconfig`
    fi
    $IFCONFIG -a > $LOC/'ifconfig.txt'

    # logs
    # httpd access logs
    {
        if [ -e /var/log/apache2/access.log ]
        then 
            # debian/ubuntu
            cat /var/log/apache2/access.log
        elif [ -e /var/log/httpd-access.log ]
        then 
            # freebsd
            cat /var/log/httpd-access.log
        else
            # centos/redhat
            cat /var/log/httpd/access_log
        fi
    } > $LOC/'httpd_accesslog.txt'

    # httpd error logs
    {
        if [ -e /var/log/apache2/error.log ]
        then 
            # debian/ubuntu
            cat /var/log/apache2/error.log
        elif [ -e /var/log/httpd-error.log ]
        then 
            # freebsd
            cat /var/log/httpd-error.log
        else
            # centos/redhat
            cat /var/log/httpd/error_log
        fi
    } > $LOC/'httpd_errorlog.txt'

    # boot logs
    cp /var/log/boot.log $LOC/'bootlog.txt'
    # kernel logs
    cp /var/log/kern.log $LOC/'kernlog.txt'
    # auth log
    cp /var/log/auth.log $LOC/'authlog.txt'
    # security log
    cp /var/log/secure $LOC/'securelog.txt'

    # current logged in users
    if who -a &> /dev/null
    then
        who -a > $LOC/'who.txt'
    else
        cat /var/run/utmp > $LOC/'who.bin'
    fi
    # last logged in users
    if last -Fwx -f /var/log/wtmp* &> /dev/null
    then 
        last -Fwx -f /var/log/wtmp* > $LOC/'last.txt'
    else
        cp /var/log/wtmp* > $LOC/
    fi

    # kernel ring buffer messages
    {
        if dmesg -T &> /dev/null
        then 
            dmesg -T
        else
            dmesg  
        fi
    } > $LOC/'dmesg.txt'

    # version information
    {
        echo -n "kernel_name="; uname -s; 
        echo -n "nodename="; uname -n;
        echo -n "kernel_release="; uname -r;
        echo -n "kernel_version="; uname -v;
        echo -n "machine="; uname -m;
        echo -n "processor="; uname -p;
        echo -n "hardware_platform="; uname -i; 
        echo -n "os="; uname -o;

    } > $LOC/'version.txt'

    # kernel modules
    lsmod | sed 1d > $TMP
    while read module size usedby
    do
        {
            echo -e $module'\t'$size'\t'$usedby;
            modprobe --show-depends $module;
            modinfo $module;
            echo "";
        } >> $LOC/'modules.txt'
    done < $TMP
    rm $TMP

    # list of PCI devices
    if [ -x /sbin/lspci ]
    then 
        # rhel5
        LSPCI=/sbin/lspci
    else
        LSPCI=`which ifconfig`
    fi
    $LSPCI > $LOC/'lspci.txt'

    # locale information
    locale > $LOC/'locale.txt'

    # user accounts
    cp /etc/passwd $LOC

    # user groups
    cp /etc/group $LOC

    # user accounts
    {
        while read line
        do
            user=`echo "$line" | cut -d':' -f1`
            pw=`echo "$line" | cut -d':' -f2`
            # ignore the salt and hash, but capture the hashing method
            hsh_method=`echo "$pw" | cut -d'$' -f2`
            rest=`echo "$line" | cut -d':' -f3,4,5,6,7,8,9`
            echo "$user:$hsh_method:$rest"
        done < /etc/shadow
    } > $LOC/'shadow.txt'

    # userprofile
    while read line
    do
        user=`echo "$line" | cut -f1 -d:`
        home=`echo "$line" | cut -f6 -d:`
        mkdir $LOC/userprofiles/$user
        # user contabs
        crontab -u $user -l > $LOC/userprofiles/$user/'crontab.txt'
        # ssh known hosts
        cp $home/.ssh/known_hosts $LOC/userprofiles/$user/'ssh_known_hosts.txt'
        # ssh config
        cp $home/.ssh/config $LOC/userprofiles/$user/'ssh_config.txt'
        # user shell history
        for f in $home/.*_history; do
            count=0
            while read line
            do
                echo $f $count $line >> $LOC/userprofiles/$user/'shellhistory.txt'
                count=$(( $count + 1 ))
            done < $f
        done
    done < /etc/passwd
}

# run collect and catch errors
ERRORS=$(collect 2>&1)
# log errors
echo "$ERRORS" > $ERROR_LOG

#
# compression and cleanup
#

cd $LOC
if [ -x zip ]
then
    zip -9r /tmp/$IRCASE'.zip' * > /dev/null
else
    tar -zcvf /tmp/$IRCASE'.tar.gz' * > /dev/null
fi
cd /tmp
rm -r $LOC
