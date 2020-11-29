#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define MAX_TABLE_SIZE 3000

RoutingTableEntry RoutingTable[MAX_TABLE_SIZE];
size_t current_size = 0;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

void _insert(RoutingTableEntry entry) {
    //printf("insert one, addr=%s, nexthop=%s, len=%d, if_index=%d, addr=%u\n", inet_ntoa(in_addr{entry.addr}), inet_ntoa(in_addr{entry.nexthop}), entry.len, entry.if_index, entry.addr);
    bool exist = false;
    uint32_t addr = entry.addr;
    uint32_t len = entry.len;
    uint32_t if_index = entry.if_index;
    uint32_t nexthop = entry.nexthop;
    entry.addr = entry.addr & 0xFFFFFFFF;
    for(size_t i = 0; i < current_size; i++) {
        if (addr == RoutingTable[i].addr && len == RoutingTable[i].len) {
            RoutingTable[i].nexthop = nexthop;
            RoutingTable[i].if_index = if_index;
            exist = true;
            break;
        }
    }
    if (!exist) RoutingTable[current_size++] = entry;
    //print_routing_table();
}

void _delete(RoutingTableEntry entry) {
    uint32_t addr = entry.addr;
    uint32_t len = entry.len;
    //printf("delete one, addr=%s, nexthop=%s\n", inet_ntoa(in_addr{entry.addr}), inet_ntoa(in_addr{entry.nexthop}));
    for(size_t i = 0; i < current_size; i++) {
        if (addr == RoutingTable[i].addr && len == RoutingTable[i].len) {
            current_size--;
            RoutingTable[i] = RoutingTable[current_size];
            break;
        }
    }
    //print_routing_table();
}

void print_ip_big_endian(uint32_t ip_addr) {
    printf("%u.%u.%u.%u", (ip_addr & 0xff000000) >> 24, (ip_addr & 0x00ff0000) >> 16, (ip_addr & 0xff00) >> 8, (ip_addr & 0xff));
}

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len **精确** 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  insert ? _insert(entry) : _delete(entry);
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  //printf("prefix query");
  //print_ip_big_endian(addr);
  *nexthop = 0;
  *if_index = 0;
  int index = -1;
  int max_len = 0;
  //print_routing_table();
  for(size_t i = 0; i < current_size; i++) {
      uint32_t mask = ((uint64_t)1<<RoutingTable[i].len) - 1;
      //printf("addr= %s | entry: mask=%d, addr=%s, len=%d, if_index=%d | addr&mask=%s\n", inet_ntoa(in_addr{htonl(addr)}), mask, inet_ntoa(in_addr{htonl(RoutingTable[i].addr)}), RoutingTable[i].len, RoutingTable[i].if_index, inet_ntoa(in_addr{htonl(addr & mask)}));
      //printf("%u, %u, %s, %s\n", addr&mask, RoutingTable[i].addr, inet_ntoa(in_addr{htonl(addr&mask)}), inet_ntoa(in_addr{htonl(RoutingTable[i].addr)}));
      //print_ip_big_endian(RoutingTable[i].addr);
      if ((addr & mask) == RoutingTable[i].addr && RoutingTable[i].len > max_len) {
          //printf("Found one\n");
          max_len = RoutingTable[i].len;
          index = i;
      }
  }
  if (index < 0) {
      //printf("!!!Not Found in Routing Table!!!");
      return false;
  }
  *nexthop = RoutingTable[index].nexthop;
  *if_index = RoutingTable[index].if_index;
  return true;
}
