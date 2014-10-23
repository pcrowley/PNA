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

# userspace module files

MAIN_PROG := pna
COMMON_OBJS := pna_main.o pna_config.o pna_flowmon.o pna_domain_trie.o
COMMON_OBJS += pna_rtmon.o util.o

LIBS := -lpcap

EXTRA_CFLAGS += -I$(PWD)/../include/ $(LIBS)

all: ${MAIN_PROG}

${MAIN_PROG}: ${MAIN_PROG}.o ${COMMON_OBJS}
	$(CC) $(EXTRA_CFLAGS) $< ${COMMON_OBJS} -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
