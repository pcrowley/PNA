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

#include <linux/module.h>
#include <linux/moduleparam.h>

/* configuration parameters */
char *pna_iface = "eth0";
uint pna_prefix = 0xc0a80000; /* 192.168.0.0    */
uint pna_mask = 0xffff0000;   /*            /16 */
uint pna_tables = 2;
uint pna_connections = 0xffffffff;
uint pna_sessions = 0xffffffff;
uint pna_tcp_ports = 0xffffffff;
uint pna_tcp_bytes = 0xffffffff;
uint pna_tcp_packets = 0xffffffff;
uint pna_udp_ports = 0xffffffff;
uint pna_udp_bytes = 0xffffffff;
uint pna_udp_packets = 0xffffffff;
uint pna_ports = 0xffffffff;
uint pna_bytes = 0xffffffff;
uint pna_packets = 0xffffffff;
bool pna_debug = false;
bool pna_perfmon = true;

bool pna_flowmon = true;
bool pna_rtmon = true;

module_param(pna_iface, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_iface, "Interface on which we listen to packets");
module_param(pna_prefix, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_prefix, "Network prefix defining 'local' IP addresses");
module_param(pna_mask, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_mask, "Network mask for IP addresses");
module_param(pna_tables, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tables, "Number of <src,dst,port> tables to use");

module_param(pna_connections, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_connections, "Number of connections to trigger alert");
module_param(pna_sessions, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_sessions, "Number of sessions to trigger alert");
module_param(pna_tcp_ports, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tcp_ports, "Number of TCP ports to trigger alert");
module_param(pna_tcp_bytes, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tcp_bytes, "Number of TCP bytes to trigger alert");
module_param(pna_tcp_packets, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tcp_packets, "Number of TCP packets to trigger alert");
module_param(pna_udp_ports, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_udp_ports, "Number of UDP ports to trigger alert");
module_param(pna_udp_bytes, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_udp_bytes, "Number of UDP bytes to trigger alert");
module_param(pna_udp_packets, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_udp_packets, "Number of TCP packets to trigger alert");
module_param(pna_ports, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_ports, "Number of total ports to trigger alert");
module_param(pna_bytes, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_bytes, "Number of total bytes to trigger alert");
module_param(pna_packets, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_packets, "Number of total packets to trigger alert");

module_param(pna_debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_debug, "Enable kernel debug log messages");
module_param(pna_perfmon, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_perfmon, "Enable PNA performance monitoring messages");
module_param(pna_flowmon, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_flowmon, "Enable PNA flow monitoring");
module_param(pna_rtmon, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_rtmon, "Enable PNA real-time monitoring (if pna_flowmon)");
