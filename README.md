# Passive Network Appliance Node Software #

This software is designed to monitor all traffic arriving at a network
card, extract summary statistics, insert that packet into a session table, and
periodically dump that session table to a file on disk.  The Linux kernel
module found in `module/` handles the packet reception and table insertion
routines.  It also allows arbitrary real-time monitors to be executed for
each packet received.  Every 10 seconds a user-space program (in `user/`)
executes and extracts the previously logged summary statistics, creating a
dump file with all the data in it.

## Instructions ##

The Passive Network Appliance (PNA) software has been built against Linux
kernel 2.6.34 and 2.6.37 without error, it should work against other kernel
versions as well--assuming there have not been major changes.

Building can be done by typing `make` in the top level directory.  This
will build the kernel module (found in `module/`) and the user-space programs
(found in `user/`).

Loading the kernel module and user-space programs is done with a script
(`service/pna`).  This script takes a few configuration parameters that should
be set in the `service/config` file (see `service/config.example` or
`service/config.dynamic`, for examples):

 - `PNA_BASE` sets the base directory of the PNA software (i.e. `pwd` of this file)
 - `PNA_IFACE` sets the interface on which traffic will be monitored
 - `PNA_PREFIX` sets the IP prefix of the monitored network (local network)
 - `PNA_MASK` sets the subnet mask of the monitored network
 - `PNA_LOGDIR` sets the location to store the logged statistics

Nothing else should need modification.

You will need to be a `sudo` capable user to load the kernel module and
configure the system.  The script can be run by typing `make start` from
the top level directory. This will load the kernel module and start the 
user-space programs.  If there is traffic, log files should appear in 
`PNA_LOGDIR` after 10 seconds. You can stop all the software at any time
by running `make stop` from the top level directory.  This will unload
the kernel module and kill any user-space processes.

Optionally, there are scripts in `util/cron/` that can be used to move the
log files elsewhere as needed.  There is also a command line interface
`util/intop/cli.py` that can process log files and print out the summary
statistics in a useful format.

## File Manifest ##

Below is an approximate description of the various folders and files in
this project.

 - `include/` contains the header file(s) for the PNA software
 - `module/` contains the kernel module source code
   - `pna_main.c` is the entry point for the kernel module (initialization
     and hooking
   - `pna_session.c` has routines to insert the packet into a session entry
     and deals with exporting the summary statistics to user-space
   - `pna_rtmon.c` is the handler for real-time monitors
   - `pna_alert.c` is code to send messages to a user-space process when a
     real-time monitor detects anomalous behavior
   - `pna_config.c` handles run-time configuration parameters
 - `monitors/` contains existing real-time monitors
   - `pna_lipmon.c` is a local IP monitor (tracks stats on local IPs)
   - `pna_conmon.c` is a connection monitor (tracks per-connection stats)
 - `service/` contains configuration and start/stop scripts
   - `pna` is the script to start, stop, load, or unload any PNA software
   - `config` MUST be created. Included is an example configuration and a 
     "best guess" dynamic configuration (can be symlinked)
 - `user/` has the user-space software
   - `user_monitor.c` interacts with the session tables to export them to a
     log file
   - `user_alerts.c` is the alert handler for real-time monitors
 - `util/cron/` contains scripts and crontabs that help move files off-site
 - `util/intop/` contains software to help read and process the log files

## License ##

Copyright 2011 Washington University in St Louis

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

> Please see `LICENSE` for more details.
