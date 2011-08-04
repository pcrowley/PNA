#!/bin/sh
# This gets relevant pna performance data from /var/log/messages on the PNA
# host

OUTPUT_DIR="/home/pna/pna/syslogs"

mkdir -p $OUTPUT_DIR

# Set output file date
DATE=$(date --date='yesterday' +'%F')

# Date log files will contain
LOG_DATE=$(date --date='yesterday' +'%b %e')

# Log files to search (two most recent covers a day)
LOGS="/var/log/messages.1 /var/log/messages"

# grep string to match
KEYWORDS="pna \(throughput\|table\|\([A-Za-z]\+[0-9]\+ \)\?rx_stats\)"
GREP_STRING="^$LOG_DATE.*$KEYWORDS"

LOG_FILE="$OUTPUT_DIR/messages_$DATE"
sudo grep -h "$GREP_STRING" $LOGS > $LOG_FILE
