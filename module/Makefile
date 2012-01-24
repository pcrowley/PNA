# Copyright 2011 Washington University in St Louis
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# kernel module files

obj-m += pna.o
pna-objs := pna_main.o pna_config.o pna_flowmon.o
pna-objs += pna_hashmap.o murmur3.o
pna-objs += pna_alerts.o pna_rtmon.o
pna-objs += pna_rtmon-conlip.o

KDIR := /lib/modules/`uname -r`/build
EXTRA_CFLAGS += -I$(PWD)/../include/

all: module $(user-progs)

module:
	$(MAKE) -C $(KDIR) M=`pwd` modules

clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean
	rm -f Module.markers
