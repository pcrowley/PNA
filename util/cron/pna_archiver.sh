#!/bin/bash
# Given a collection of compressed 10 minute archives,
# create a archive of all the log files for 1 day

ARCHIVE_DIR="/usr/local/pna/archive"
PERIODIC_DIR="$ARCHIVE_DIR/daily"

SSH_OPTIONS="-i /home/mjschultz/.ssh/pna_rsa"
REMOTE_LOCATION="mjschultz@10.0.16.4:/var/pna/archive"

# Find out what yesterday's date prefix is
ARCHIVE_TIME=$(date --date='12 hours ago' +%Y%m%d%H%M%S)
ARCHIVE_TIME=${ARCHIVE_TIME:0:$((${#ARCHIVE_TIME}-6))}
ARCHIVE="$ARCHIVE_DIR/logs-$ARCHIVE_TIME.tar"

# Loop over all files matching that prefix in the daily/ directory
for archive in $PERIODIC_DIR/$ARCHIVE_TIME* ; do
    TEMP="$ARCHIVE_DIR/.$ARCHIVE_TIME.tmp.tar"
    # Uncompress (and keep) daily/* putting just .tar in temp folder
    bunzip -c $archive > $TEMP
    # Concatenate .tar file into day prefix tar file
    tar --concatenate --file $ARCHIVE $TEMP
    # Remove .tar in temp folder
    rm -f $TEMP
done

# Move two day old archives to pna02
ARCHIVES=`find $ARCHIVE_DIR -ctime +1`
for archive in $ARCHIVES ; do
    # If it isn't a file skip it
    if [ ! -f $archive ] ; then
        continue
    fi

    # Attempt to copy to REMOTE_LOCATION
    scp $SSH_OPTIONS $archive $REMOTE_LOCATION

    # If successful, remove the local copy
    if [ $? -eq 0 ] ; then
        rm -f $archive
    fi
done

# Remove one day old periodic files 
ARCHIVES=`find $PERIODIC_DIR -ctime +0`
for archive in $ARCHIVES ; do
    rm -f $archive
done

