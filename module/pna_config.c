/**
 * Copyright 2011 Washington University in St Louis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* PNA configuration values */
#include "pna.h"

/* configuration parameters */
char *pna_iface = "eth0";
unsigned int pna_tables = 2;
unsigned int pna_bits = 16;
unsigned int pna_connections = 0xffffffff;
unsigned int pna_sessions = 0xffffffff;
unsigned int pna_tcp_ports = 0xffffffff;
unsigned int pna_tcp_bytes = 0xffffffff;
unsigned int pna_tcp_packets = 0xffffffff;
unsigned int pna_udp_ports = 0xffffffff;
unsigned int pna_udp_bytes = 0xffffffff;
unsigned int pna_udp_packets = 0xffffffff;
unsigned int pna_ports = 0xffffffff;
unsigned int pna_bytes = 0xffffffff;
unsigned int pna_packets = 0xffffffff;
bool pna_debug = false;
bool pna_perfmon = true;

bool pna_flowmon = true;
bool pna_rtmon = false;

/*
MODULE_PARM_DESC(pna_iface, "Interface on which we listen to packets");
MODULE_PARM_DESC(pna_tables, "Number of <src,dst,port> tables to use");
MODULE_PARM_DESC(pna_bits, "Bits to use for hash table sizing (2^n)");

MODULE_PARM_DESC(pna_connections, "Number of connections to trigger alert");
MODULE_PARM_DESC(pna_sessions, "Number of sessions to trigger alert");
MODULE_PARM_DESC(pna_tcp_ports, "Number of TCP ports to trigger alert");
MODULE_PARM_DESC(pna_tcp_bytes, "Number of TCP bytes to trigger alert");
MODULE_PARM_DESC(pna_tcp_packets, "Number of TCP packets to trigger alert");
MODULE_PARM_DESC(pna_udp_ports, "Number of UDP ports to trigger alert");
MODULE_PARM_DESC(pna_udp_bytes, "Number of UDP bytes to trigger alert");
MODULE_PARM_DESC(pna_udp_packets, "Number of TCP packets to trigger alert");
MODULE_PARM_DESC(pna_ports, "Number of total ports to trigger alert");
MODULE_PARM_DESC(pna_bytes, "Number of total bytes to trigger alert");
MODULE_PARM_DESC(pna_packets, "Number of total packets to trigger alert");

MODULE_PARM_DESC(pna_debug, "Enable kernel debug log messages");
MODULE_PARM_DESC(pna_perfmon, "Enable PNA performance monitoring messages");
MODULE_PARM_DESC(pna_flowmon, "Enable PNA flow monitoring");
MODULE_PARM_DESC(pna_rtmon, "Enable PNA real-time monitoring (if pna_flowmon)");
*/
