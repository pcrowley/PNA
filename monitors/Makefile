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

# real-time monitor files

obj-m += pna_lipmon.o pna_conmon.o

ifndef BASE
    BASE = $(PWD)/..
endif

KDIR := /lib/modules/`uname -r`/build
EXTRA_CFLAGS += -I$(PWD)/../include/
PNA_DIR := $(BASE)/module
PNA_SYMBOLS := $(PNA_DIR)/Module.symvers

all: modules

modules:
	$(MAKE) -C $(PNA_DIR)
	$(MAKE) -C $(KDIR) M=`pwd` KBUILD_EXTRA_SYMBOLS=$(PNA_SYMBOLS) modules

clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean
	rm -f Module.markers
