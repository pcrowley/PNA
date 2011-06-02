#!/bin/bash

BASE="/home/mjschultz"
CRON="$BASE/pna/util/cron"

LOG_DIR="$BASE/pna/logs"
ARCHIVE_DIR="$CRON/archive"

SSH_OPTIONS="-i $BASE/.ssh/pna_rsa"
REMOTE_LOCATION="mjschultz@mcore.arl.wustl.edu:~/archive/daily"

# Figure out what log files to look for
ARCHIVE_TIME=$(date --date='5 minutes ago' +%Y%m%d%H%M%S)
ARCHIVE_TIME=${ARCHIVE_TIME:0:$((${#ARCHIVE_TIME}-3))}
ARCHIVE="$ARCHIVE_DIR/$ARCHIVE_TIME.tar"

# Make sure the archive directory is there
mkdir -p $ARCHIVE_DIR

# Archive and cleanup logs matching ARCHIVE_TIME
pushd $LOG_DIR > /dev/null
	tar cf $ARCHIVE pna-$ARCHIVE_TIME*.log
	tar tf $ARCHIVE | xargs rm
	bzip2 $ARCHIVE
popd > /dev/null

# Attempt to copy this and any older archives to remote host
for archive in $ARCHIVE_DIR/* ; do
	# If it isn't a file, skip it
	if [ ! -f $archive ] ; then
		continue
	fi

	# Attempt to copy to REMOTE_LOCATION
	scp $SSH_OPTIONS $archive $REMOTE_LOCATION

	# If successful, remove the local archive
	if [ $? -eq 0 ] ; then
		rm -f $archive
	fi
done

# TODO: Check for any log file stragglers
