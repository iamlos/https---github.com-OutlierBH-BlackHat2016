#!/bin/ksh

# usage: sudo sh presponse.sh

# Set up variables
IRCASE=`hostname`-`date +%m%d%Y`
LOC=/tmp/$IRCASE
TMP=$LOC/$IRCASE'_tmp.txt'
mkdir $LOC

# Collect
# Change snap output path to $LOC
snap -d $LOC
snap -a 2> /dev/null

for user in $(cut -f1 -d: /etc/passwd)
do
     (echo $user
      crontab -l $user
      echo " ") >> $LOC/$IRCASE'_aix-crontab-users.txt' 2>&1
done

uname -s > $LOC/$IRCASE'_aix-version.txt' 2> /dev/null
uname -r >> $LOC/$IRCASE'_aix-version.txt' 2> /dev/null
uname -v >> $LOC/$IRCASE'_aix-version.txt' 2> /dev/null
ifconfig -a > $LOC/$IRCASE'_aix-ifconfig.txt' 2> /dev/null
ls -ALmRt1 > $LOC/$IRCASE'_aix-ls.txt' 2> /dev/null
cat /etc/passwd > $LOC/$IRCASE'_aix-passwd.txt' 2> /dev/null
cat /etc/shadow > $LOC/$IRCASE'_aix-shadow.txt' 2> /dev/null
cat /etc/group > $LOC/$IRCASE'_aix-group.txt' 2> /dev/null
ps gcleww > $LOC/$IRCASE'_aix-ps.txt' 2> /dev/null
netstat -an > $LOC/$IRCASE'_aix-netstat.txt' 2> /dev/null

errpt -a > $LOC/$IRCASE'_aix-errpt.txt' 2> /dev/null
genkld > $LOC/$IRCASE'_aix-genkld.txt' 2> /dev/null
genld -l > $LOC/$IRCASE'_aix-genld.txt' 2> /dev/null
genkex > $LOC/$IRCASE'_aix-genkex.txt' 2> /dev/null
locale > $LOC/$IRCASE'_aix-locale.txt' 2> /dev/null
logins > $LOC/$IRCASE'_aix-logins.txt' 2> /dev/null
at -al > $LOC/$IRCASE'_aix-at.txt' 2> /dev/null
cronadm cron -l > $LOC/$IRCASE'_aix-cronadm.txt' 2> /dev/null
lssrc -a > $LOC/$IRCASE'_aix-lssrc.txt' 2> /dev/null
cat /var/log/authlog > $LOC/$IRCASE'_aix-authlog.txt' 2> /dev/null
cat /var/log/messages > $LOC/$IRCASE'_aix-messages.txt' 2> /dev/null

cat /etc/cron.allow > $LOC/$IRCASE'_aix-cronallow.txt' 2> /dev/null
cat /etc/crontab > $LOC/$IRCASE'_aix-crontab.txt' 2> /dev/null
ls -al /etc/cron.* > $LOC/$IRCASE'_aix-cronfiles.txt' 2> /dev/null
cat /var/log/secure > $LOC/$IRCASE'_aix-securelog.txt' 2> /dev/null
cat /var/adm/utmp > $LOC/$IRCASE'_aix-utmplog.txt' 2> /dev/null
cat /var/adm/wtmp > $LOC/$IRCASE'_aix-wtmplog.txt' 2> /dev/null

# Run snap -c on the $LOC; this should produce /tmp/snap.pax.Z
snap -c
mv tmp/snap.pax.Z /tmp/$IRCASE'.pax.Z' 2> /dev/null
rm -r $LOC
