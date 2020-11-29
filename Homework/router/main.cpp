#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

uint8_t packet[2048];
uint8_t output[2048];
const uint32_t RIP_MULTICAST_ADDR = 0x090000e0;

// Routing table: linear data structure
extern RoutingTableEntry RoutingTable[];
extern size_t current_size;

// for online experiment, don't change
#ifdef ROUTER_R1
// 0: 192.168.1.1
// 1: 192.168.3.1
// 2: 192.168.6.1
// 3: 192.168.7.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0101a8c0, 0x0103a8c0, 0x0106a8c0,
                                           0x0107a8c0};
#elif defined(ROUTER_R2)
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 192.168.8.1
// 3: 192.168.9.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0108a8c0,
                                           0x0109a8c0};
#elif defined(ROUTER_R3)
// 0: 192.168.4.2
// 1: 192.168.5.2
// 2: 192.168.10.1
// 3: 192.168.11.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0204a8c0, 0x0205a8c0, 0x010aa8c0,
                                           0x010ba8c0};
#else

// 自己调试用，你可以按需进行修改，注意端序
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
                                     0x0103000a};
#endif

macaddr_t multicast_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};

RipPacket** rip_router_table(bool is_request, int interface, int *packet_num) {
    printf("rip_router_table(): construct rip_packets, is_request=%d\n", is_request);
    RipPacket** rip_packets = new RipPacket*[210];
    //printf("function rip_router_table\n");
    *packet_num = 0;
    //printf("after construct rip_packets\n");
    if (is_request) {
        printf("is request\n");
        *packet_num = 1;
        rip_packets[0] = new RipPacket();
        rip_packets[0]->numEntries = 1;
        rip_packets[0]->command = 0x01;
        RipEntry entry = {
            .addr = 0x00000000,
            .mask = 0x00000000,
            .nexthop = 0x00000000,
            .metric = 0x10000000
        };
        rip_packets[0]->entries[0] = entry;
    } else {
        printf("not request, Size = %d\n", current_size);
        for (size_t i = 0; i < current_size; i++) {
            if (i % 25 == 0) {
                rip_packets[*packet_num] = new RipPacket();
                rip_packets[*packet_num]->numEntries = (current_size - i >= 25) ? 25 : current_size - i;
                rip_packets[*packet_num]->command = 0x02;
                *packet_num = *packet_num + 1;
            }
            //printf("before construct entry %d\n", i);
            RipEntry entry = {
                .addr = RoutingTable[i].addr,
                .mask = 0,
                .nexthop = RoutingTable[i].nexthop,
                .metric = (interface == RoutingTable[i].if_index) ? 0x10000000 : RoutingTable[i].metric
            };
            //printf("after construct entry %d\n", i);
            uint32_t mask = 0;
            for (size_t j = 0; j < RoutingTable[i].len; j++) {
                mask = (mask << 1) + 1;
            }
            for (size_t j = RoutingTable[i].len; j < 32; j++) {
                mask = (mask << 1);
            }
            entry.mask = htonl(mask);
            printf("entry %d mask: %d \n", i, entry.mask);
            rip_packets[*packet_num-1]->entries[i % 25] = entry;   
        }
    }
    return rip_packets;
}

void send_message(int interface, bool is_request, uint32_t dst_addr, macaddr_t mac_addr) {
    int packet_num = 0;
    printf("send message, if_index=%d, dst_addr=%d.%d.%d.%d \n", interface, dst_addr & 0xff, (dst_addr & 0xff00) >> 8, (dst_addr & 0xff0000) >> 16, (dst_addr & 0xff000000) >> 24);
    RipPacket** rip_packets = rip_router_table(is_request, interface, &packet_num);
    for (size_t i = 0; i < packet_num; i++) {
        printf("packet num: %d\n", i);
        int rip_len = assemble(rip_packets[i], output+28); //UDP包中套RIP包
        output[0] = 0x45; // version = 4, IHL = 5
        output[1] = 0x00; // type of service = 0
        int ip_len = rip_len + 28; // total length
        output[2] = (ip_len & 0xff00) >> 8;
        output[3] = ip_len & 0xff;
        output[4] = output[5] = output[6] = output[7] = 0x0; // flags
        output[8] = 0x01; // ttl = 1
        output[9] = 0x11; // protocol: udp = 17
        output[10] = output[11] = 0x00; // set checksum to zero for future calculation
        // src addr
        uint32_t src_addr_net = htonl(addrs[interface]);
        output[12] = (src_addr_net & 0xff000000) >> 24;
        output[13] = (src_addr_net & 0x00ff0000) >> 16;
        output[14] = (src_addr_net & 0x0000ff00) >> 8;
        output[15] = (src_addr_net & 0x000000ff);
        // dst addr
        uint32_t dst_addr_net = htonl(dst_addr);
        output[16] = (dst_addr_net & 0xff000000) >> 24;
        output[17] = (dst_addr_net & 0x00ff0000) >> 16;
        output[18] = (dst_addr_net & 0x0000ff00) >> 8;
        output[19] = (dst_addr_net & 0x000000ff);
        // checksum
        uint16_t checksum = 0;
        uint32_t sum = 0;
        for (size_t i = 0; i < 20; i += 2) { 
            sum += (((uint16_t)output[i]) << 8) + output[i+1];
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        checksum = (uint16_t)(~sum);
        output[10] = (checksum & 0xff00) >> 8;
        output[11] = checksum & 0xff;
        // UDP
        output[20] = 0x02; // src port
        output[21] = 0x08;
        output[22] = 0x02; // dst port
        output[23] = 0x08;
        int udp_len = rip_len + 8;
        printf("udp length: %d\n", udp_len);
        output[24] = (udp_len & 0xff00) >> 8;
        output[25] = udp_len & 0xff;
        output[26] = output[27] = 0x00; //UDP校验和可空，置零，可以不计算
        // send
        HAL_SendIPPacket(interface, output, ip_len, mac_addr);
    }
}

void swap(uint8_t& a, uint8_t& b) {
    uint8_t temp = a;
    a = b;
    b = temp;
}

void cal_ip_icmp_checksum(size_t total_length) {
    // calculate icmp checksum and ip checksum
    output[10] = output[11] = 0x00;
    output[22] = output[23] = 0x00;
    output[total_length] = 0x00; // padding for case: total-len is odd
    // ip checksum
    uint16_t checksum = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < 20; i += 2) { 
        sum += (((uint16_t)output[i]) << 8) + output[i+1];
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    checksum = (uint16_t)(~sum);
    output[10] = (checksum & 0xff00) >> 8;
    output[11] = checksum & 0xff;
    // icmp checksum
    checksum = 0;
    sum = 0;
    for (size_t i = 20; i < total_length; i += 2) {
        sum += (((uint16_t)output[i]) << 8) + output[i+1];
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    checksum = (uint16_t)(~sum);
    output[22] = (checksum & 0xff00) >> 8;
    output[23] = checksum & 0xff;
}

void print_routing_table() {
    printf("Routing Table Info: Size = %d\n", current_size);
    for (size_t i = 0; i < current_size; i++) {
        uint32_t addr = ntohl(RoutingTable[i].addr);
        printf("%u.%u.%u.%u, ", (addr & 0xff000000) >> 24, (addr & 0x00ff0000) >> 16, (addr & 0xff00) >> 8, (addr & 0xff));
        uint32_t len = RoutingTable[i].len;
        printf("len: %d, ", len);
        uint32_t nexthop = RoutingTable[i].nexthop;
        if (nexthop == 0) {
            printf("straight route, dev %d scope link, ", RoutingTable[i].if_index);
        } else {
            printf("via %u.%u.%u.%u ", (nexthop & 0xff000000) >> 24, (nexthop & 0xff0000) >> 16, (nexthop & 0xff00) >> 8, nexthop & 0xff);
            printf(" dev %d, ", RoutingTable[i].if_index);
        }
        printf("metric: %d \n", (RoutingTable[i].metric & 0xff000000) >> 24);
    }
}


int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,                     // little endian
        .if_index = i,                 // little endian
        .nexthop = 0,                  // big endian, means direct
        .metric = 0x01000000           // big endian, set direct routes to 1
    };
    update(true, entry);
  }
  print_routing_table();
  uint64_t last_time = 0;

  //send_message(0, true, RIP_MULTICAST_ADDR, multicast_mac);
  //send_message(1, true, RIP_MULTICAST_ADDR, multicast_mac);

  while (1) {
    printf("***************************************");
    uint64_t time = HAL_GetTicks();
    // the RFC says 30s interval,
    // but for faster convergence, use 5s here
    if (time > last_time + 5 * 1000) {
      // ref. RFC2453 Section 3.8
      print_routing_table();
      printf("5s Timer\n");
      // HINT: print complete routing table to stdout/stderr for debugging
      // TODO: send complete routing table to every interface
      for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
        // construct rip response
        // do the mostly same thing as step 3a.3
        // except that dst_ip is RIP multicast IP 224.0.0.9
        // and dst_mac is RIP multicast MAC 01:00:5e:00:00:09
        send_message(i, false, RIP_MULTICAST_ADDR, multicast_mac);
      }
      //print_routing_table();
      last_time = time;
    }

    uint32_t mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }
    printf("receive a packet, res: %d \n", res);
    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("!!!receive packet Invalid IP Checksum!!!\n");
      // drop if ip checksum invalid
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // TODO: extract src_addr and dst_addr from packet (big endian)
    src_addr = (packet[15] << 24) + (packet[14] << 16) + (packet[13] << 8) + packet[12]; // big
    dst_addr = (packet[19] << 24) + (packet[18] << 16) + (packet[17] << 8) + packet[16]; // big
    printf("packet addr info from %d: ", if_index);
    printf("src addr = %d.%d.%d.%d ", src_addr & 0xff, (src_addr & 0xff00) >> 8, (src_addr & 0xff0000) >> 16, (src_addr & 0xff000000) >> 24);
    printf("dst addr = %d.%d.%d.%d \n", dst_addr & 0xff, (dst_addr & 0xff00) >> 8, (dst_addr & 0xff0000) >> 16, (dst_addr & 0xff000000) >> 24);
    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: handle rip multicast address(224.0.0.9)

    if (dst_is_me || dst_addr == RIP_MULTICAST_ADDR) {
      printf("dst is me\n");
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        printf("rip command: %d\n", rip.command);
        if (rip.command == 1) {
          printf("3a.3 request\n");
          // 3a.3 request, ref. RFC2453 Section 3.9.1
          // only need to respond to whole table requests in the lab
          // RipPacket resp;
          // TODO: fill resp
          // implement split horizon with poisoned reverse
          // ref. RFC2453 Section 3.4.3

          // TODO: fill IP headers
          // output[0] = 0x45;

          // TODO: fill UDP headers
          // port = 520
          // output[20] = 0x02;
          // output[21] = 0x08;

          // assembleRIP
          // uint32_t rip_len = assemble(&resp, &output[20 + 8]);

          // TODO: checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero

          // send it back
          // HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
          send_message(if_index, false, src_addr, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 Section 3.9.2
          // TODO: update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // HINT: handle nexthop = 0 case
          // HINT: what is missing from RoutingTableEntry?
          // you might want to use `prefix_query` and `update`, but beware of
          // the difference between exact match and longest prefix match.
          // optional: triggered updates ref. RFC2453 3.10.1
          printf("Update Routing Table... num_entries: %d\n", rip.numEntries);
          for (size_t i = 0; i < rip.numEntries; i++) {
              uint32_t len = 32;
              uint32_t ite = ntohl(rip.entries[i].mask);
              while(!(ite & 1) && len > 0) { // calculate length
                  len --;
                  ite >>= 1;
              }
              uint8_t entry_metric = (rip.entries[i].metric & 0xff000000) >> 24;
              if (entry_metric >= 15) continue; //对metric为16的包直接丢弃
              entry_metric ++;
              RoutingTableEntry entry = {
                  .addr = rip.entries[i].addr,
                  .len = len,
                  .if_index = if_index,
                  .nexthop = htonl(src_addr),
                  .metric = ((uint32_t)entry_metric) << 24 // big endian
              };
            //   if (rip.entries[i].nexthop == 0) {
            //       entry.metric = 0x10000000;
            //   }
              // update Routing Table
              bool exist = false;
              // linear finding, O(n)!!!
              for(size_t i = 0; i < current_size; i++) {
                if (entry.addr == RoutingTable[i].addr && entry.len == RoutingTable[i].len) {
                    if (RoutingTable[i].nexthop == entry.nexthop) { // sender address == prev nexthop in Routing Table
                        printf("Next Hop is Src Addr, force update\n");
                        print_routing_table();
                        RoutingTable[i].nexthop = entry.nexthop;
                        RoutingTable[i].if_index = entry.if_index;
                        RoutingTable[i].metric = entry.metric;
                    } else if (entry.metric < RoutingTable[i].metric) {
                        printf("Next Hop is not Src Addr, and metric is smaller than in-table entry\n");
                        print_routing_table();
                        RoutingTable[i].nexthop = entry.nexthop;
                        RoutingTable[i].if_index = entry.if_index;
                        RoutingTable[i].metric = entry.metric;
                    }
                    exist = true;
                    break;
                }
              }
              if (!exist) RoutingTable[current_size++] = entry;
           }
           print_routing_table();
        }
      } else {
        // not a rip packet
        // handle icmp echo request packet
        // TODO: how to determine?
        printf("IP packet illgel\n");
        uint8_t ip_protocol = packet[9];
        uint8_t icmp_type = packet[20]; // icmp type: 8 for echo message
        bool is_echo_reply = ip_protocol == 0x01 && icmp_type == 0x08;
        if (is_echo_reply) {
          // TODO: construct icmp echo reply
          // reply is mostly the same as request,
          // you need to:
          // 1. swap src ip addr and dst ip addr
          // 2. change icmp `type` in header
          // 3. set ttl to 64
          // 4. re-calculate icmp checksum and ip checksum
          printf("echo reply...");
          memcpy(output, packet, res);
          // swap src and dst addr
          swap(output[12], output[16]);
          swap(output[13], output[17]);
          swap(output[14], output[18]);
          swap(output[15], output[19]);
          output[8] = 64; // ttl = 64
          // icmp type
          output[20] = 0x00; // icmp type: 0 for echo reply message
          // ip & icmp checksum
          // only calculate icmp packet checksum
          uint32_t total_length = (packet[2] << 8) + packet[3];
          cal_ip_icmp_checksum(total_length);
          HAL_SendIPPacket(if_index, output, res, src_mac);
        }
      }
    } else {
      // 3b.1 dst is not me
      // check ttl
      printf("dst is not me...\n");
      uint8_t ttl = packet[8];
      if (ttl <= 1) {
        printf("ttl < 1 ! time to live exceeded!!\n");
        // TODO: send icmp time to live exceeded to src addr
        // fill IP header
        output[0] = 0x45;
        // ttl = 64
        output[8] = 64;
        // fill icmp header
        // icmp type = Time Exceeded
        // icmp code = 0
        // fill unused fields with zero
        // append "ip header and first 8 bytes of the original payload"
        output[20] = 11;
        output[21] = 0;
        output[24] = output[25] = output[26] = output[27] = 0;
        memcpy(output+28, packet, 28);
        uint32_t total_length = 20 + 8 + 28;
        output[2] = (total_length & 0xff00) >> 8;
        output[3] = total_length & 0xff;
        // calculate icmp checksum and ip checksum
        cal_ip_icmp_checksum(total_length);
        HAL_SendIPPacket(if_index, output, res, src_mac);
      } else {
          printf("ttl > 1, forward\n");
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (prefix_query(dst_addr, &nexthop, &dest_if)) {
          printf("prefix query hit\n");
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            printf("nexthop is zero !!!\n");
            nexthop = dst_addr;
          }
          nexthop = htonl(nexthop);
        //   if ((nexthop & 0xff000000) >> 24 == 0xc0) {
        //     nexthop = htonl(nexthop);
        //   }
          printf("nexthop: %d.%d.%d.%d, dest_if: %d\n", (nexthop & 0xff000000) >> 24, (nexthop & 0xff0000) >> 16, (nexthop & 0xff00) >> 8, nexthop & 0xff, dest_if);
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            printf("Forwarding ARP Packet");
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
            // you can drop it
            printf("ARP not found for nexthop %d.%d.%d.%d\n", (nexthop & 0xff000000) >> 24, (nexthop & 0xff0000) >> 16, (nexthop & 0xff00) >> 8, nexthop & 0xff);
          }
        } else {
          // not found
          // TODO: send ICMP Destination Network Unreachable
          printf("ICMP Destination Network Unreachable, IP not found for src %d.%d.%d.%d dst %d.%d.%d.%d\n", 
                 src_addr & 0xff, (src_addr & 0xff00) >> 8, (src_addr & 0xff0000) >> 16, (src_addr & 0xff000000) >> 24,
                 dst_addr & 0xff, (dst_addr & 0xff00) >> 8, (dst_addr & 0xff0000) >> 16, (dst_addr & 0xff000000) >> 24);
          // send icmp destination net unreachable to src addr
          // fill IP header
          output[0] = 0x45;
          // ttl = 64
          output[8] = 64;
          // fill icmp header
          // icmp type = Destination Unreachable(3)
          // icmp code = Destination Network Unreachable(0)
          // fill unused fields with zero
          // append "ip header and first 8 bytes of the original payload"
          output[20] = 3; // icmp type
          output[21] = 0; // icmp code
          output[24] = output[25] = output[26] = output[27] = 0;
          memcpy(output+28, packet, 28);
          uint32_t total_length = 20 + 8 + 28;
          output[2] = (total_length & 0xff00) >> 8;
          output[3] = total_length & 0xff;
          // calculate icmp checksum and ip checksum
          cal_ip_icmp_checksum(total_length);
          HAL_SendIPPacket(if_index, output, res, src_mac);
        }
      }
    }
  }
  return 0;
}
