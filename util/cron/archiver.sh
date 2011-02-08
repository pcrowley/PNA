#!/bin/bash

BASE="/home/mjschultz"
LOGDIR="$BASE/monitor/module/user/logs"
ARCDIR="$BASE/archive"
YESTERDATE=`date --date='1 day ago' +%Y%m%d%H%M%S`
ARCHIVE="$ARCDIR/logs-$YESTERDATE.tar"

pushd $LOGDIR > /dev/null

# Archive files older than 1 day (0 rounded up)
find . -mtime +0 ! -path './.svn*' -exec tar rf $ARCHIVE {} +

# Now remove them
tar tf $ARCHIVE | xargs rm

# And compress the archive
bzip2 $ARCHIVE

# Send it to the archival host
for a in $ARCDIR/logs-*.tar.bz2 ; do
	scp -i $BASE/.ssh/pna_rsa $a mjschultz@mcore.arl.wustl.edu:~/archive
	if [ $? -eq 0 ] ; then
		rm $a
	fi
done

popd > /dev/null
