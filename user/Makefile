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

# user-space programs
user-monitor := user_monitor
user-alerts := user_alerts
user-progs := $(user-monitor) $(user-alerts)

CFLAGS += -I../include/

all: $(user-progs)

$(user-monitor): $(user-monitor).c
	$(CC) $(CFLAGS) -o $@ $^

$(user-alerts): $(user-alerts).c
	$(CC) -ggdb $(CFLAGS) -o $@ $^

clean:
	rm -f $(user-progs)
