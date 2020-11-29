#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

bool is_mask(uint64_t mask) {
    for(size_t i = 0; i < 32; i++) {
        if ( mask == (((uint64_t)1) << i) - 1 ) { 
            return true;
        }
    }
    printf("mask = %llu \n", mask);
    return false;
}

uint64_t to_int64_net(const uint8_t *buffer, size_t bytes) { // BIG ENDIAN
    uint64_t number = 0;
    for(size_t i = 0; i < bytes; i++) {
        number = (number << 8) + buffer[i];
    }
    return number;
}

uint64_t to_int64_host(const uint8_t* buffer, size_t bytes) { // SMALL ENDIAN
    return ntohl(to_int64_net(buffer, bytes));
}

bool command_match(uint32_t rip_command, uint64_t packet_command) {
    if ((rip_command == 2 && packet_command == 2) || (rip_command == 1 && packet_command == 0)){
        return true;
    }
    printf("rip_command = %d, packet_command = %d", rip_command, packet_command);
    return false;
}

bool valid_metric(uint64_t metric) {
    return metric >= 1 && metric <= 16;
}

bool valid_entry(uint32_t command, const uint8_t* packet) {
    if ( (!command_match(command, to_int64_net(packet, 2))) ||  //family
          packet[2] != 0 || //tag
          packet[3] != 0 || //tag
          (!is_mask(to_int64_host(packet+8, 4))) ||  //mask
          (!valid_metric(to_int64_net(packet+16, 4)))      //metric
    ){
        printf("!!!invalid entry!!!, command: %d, %d | tag: %d, %d | mask: %d, %d, %d, %d | metric: %d, %d, %d, %d\n",
               packet[0], packet[1], packet[2], packet[3], packet[8], packet[9], packet[10], packet[11],
               packet[16], packet[17], packet[18], packet[19]);
        return false;
    }
    return true;
}


/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  
  typedef struct {
     !!! all fields are big endian
     !!! we don't store 'family', as it is always 2(for response) and 0(for request)
     !!! we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    !!! all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwise invalid
    !!! we don't store 'version', as it is always 2
    !!! we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的
  IP 包 由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在
  RipPacket 中额外记录了个数。 需要注意这里的地址都是用 **大端序**
  存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回
 * true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len
 * 时，把传入的 IP 包视为不合法。 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
    uint32_t iphlen = (packet[0] & 0xf) << 2;
    uint64_t ip_len = to_int64_net(packet+2, 2);
    int index = iphlen; //udp = index + iphlen
    if(ip_len > len) {
        printf("total len: %x, %x\n", packet[2], packet[3]);
        printf("!!!invalid, ip total len=%u > len=%u\n", ip_len, len);
        return false;
    }
    index += 8;
    if( (packet[index] != 1 && packet[index] != 2) || //command
         packet[index+1] != 2 ||  //version
         packet[index+2] != 0 ||  //zero
         packet[index+3] != 0     //zero
    ) {
        printf("!!!invalid, index: %d\n");
        return false;
    }
    output->command = packet[index];
    output->numEntries = 0;
    index += 4;
    while (index < len) {
        if(!valid_entry(output->command, packet+index)){
            return false;
        }
        RipEntry entry;  //little endian
        entry.addr = to_int64_host(packet+index+4, 4);
        entry.mask = to_int64_host(packet+index+8, 4);
        entry.nexthop = to_int64_host(packet+index+12, 4);
        entry.metric = to_int64_host(packet+index+16, 4);
        output->entries[output->numEntries++] = entry;
        index += 20;
    }
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 *
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括
 * Version、Zero、Address Family 和 Route Tag 这四个字段 你写入 buffer
 * 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  uint8_t command = rip->command;
  uint8_t command_value = (command == 2) ? 2 : 0;
  buffer[0] = command; //command
  buffer[1] = 2;       //version
  buffer[2] = buffer[3] = 0;       //zero
  size_t current_index = 4;
  uint8_t* entry = buffer + 4;
  size_t total_size = rip->numEntries;
  for(size_t i = 0; i < total_size; i++) {
      entry[0] = entry[2] = entry[3] = 0;
      entry[1] = command_value;
      ((uint32_t*)entry)[1] = rip->entries[i].addr;  //little endian
      ((uint32_t*)entry)[2] = rip->entries[i].mask;
      ((uint32_t*)entry)[3] = rip->entries[i].nexthop;
      ((uint32_t*)entry)[4] = rip->entries[i].metric;
      current_index += 20;
      entry += 20;
  }
  return current_index;
}
