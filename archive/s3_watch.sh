#!/bin/sh

# Check a directory to determine if a file (or files) in it have been
# superseded by a newer file.  If a file has been, transfer it to a uniqe,
# deterministic location on Amazon's S3.

# User configurable variables
SCRIPTDIR="/home/mjs/nf_ses_watch/scripts/s3_store"
TRANSFER="python2.5 ${SCRIPTDIR}/s3_put.py"
HOSTID="`hostname`"
DIRECTORY="/home/mjs/nf_ses_watch/user/binlogs"
BASENAME="nf_ses_watch"
PATH="$PATH:/usr/local/bin:/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin"

# System determined variables
SMPIDS=$(grep processor /proc/cpuinfo | awk '{print $3}')

for smpid in $SMPIDS; do
    result=`ls -1 $DIRECTORY/$BASENAME-$smpid-*.log 2> /dev/null`
    # Failed to find *any* files of that format
    if [ $? -ne 0 ]; then
        continue
    fi
	# Check if we have any files that might be old
    count=`ls -1 $DIRECTORY/$BASENAME-$smpid-*.log | wc -l`
	files=`ls -1 $DIRECTORY/$BASENAME-$smpid-*.log | sort --reverse`
	if [ $count -gt 1 ]; then
		# We have at least 2 files for that SMPID
		MODTIME=0
		for file in $files; do
			if [ -z $file ] ; then
				continue
			fi
			# Grab the first files modification time
			if [ $MODTIME -eq 0 ] ; then
				MODTIME=`stat -c %Y $file`
				continue
			fi
			# At this point the file is not the first, so it should be
			# archived
			# Sanity check: make sure the file isn't newer than the current
			MYMODTIME=`stat -c %Y $file`
			if [ $MODTIME -lt $MYMODTIME ] ; then
				echo "Alert: $file has more recent modtime than it should"
				echo "Not archiving"
			else
				${TRANSFER} $HOSTID $file
				status=$?
				if [ $status -ne 0 ] ; then
					echo -n "Alert: "
					echo "Non-zero exit status from ${TRANSFER} ($status)"
					continue
				fi
				# At this point we should be able to safely remove the file
				rm -f $file
			fi
		done
	fi
done
