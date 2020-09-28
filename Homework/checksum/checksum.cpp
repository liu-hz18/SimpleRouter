#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  len = (packet[0] & 0xf) << 2;
  uint16_t checksum;
  uint16_t sum_init = ((uint16_t)packet[10] << 8) + packet[11];
  packet[10] = packet[11] = 0;
  uint32_t sum = 0;
  for(int i = 0; i < len; i += 2) {
    uint16_t tem = (((uint16_t)packet[i]) << 8) + packet[i + 1]; //attention for BIG ENDIAN
    sum += tem;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  checksum = (uint16_t)(~sum);
  packet[10] = (checksum >> 8);
  packet[11] = (checksum & 0xff);
  return checksum == sum_init ? true : false;
}
