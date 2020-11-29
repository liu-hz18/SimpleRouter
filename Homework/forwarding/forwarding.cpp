#include <stdint.h>
#include <stdlib.h>

// 在 checksum.cpp 中定义
extern bool validateIPChecksum(uint8_t *packet, size_t len);

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以调用 checksum 题中的 validateIPChecksum 函数，
 *        编译的时候会链接进来。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
  // check checksum
  if(!validateIPChecksum(packet, len)){
      return false;
  }
  // TTL - 1
  uint16_t m = ((uint16_t)packet[8] << 8) + packet[9];
  packet[8] -= 1;
  uint16_t m_new = ((uint16_t)packet[8] << 8) + packet[9];
  // update checksum, incremental updating!!!!
  // validateIPChecksum(packet, len);
  /*
   ref: https://tools.ietf.org/html/rfc1624
    HC  - old checksum in header
    C   - one's complement sum of old header
    HC' - new checksum in header
    C'  - one's complement sum of new header
    m   - old value of a 16-bit field
    m'  - new value of a 16-bit field

    C' = C + m' - m
    HC' = ~(~HC + ~m + m')
  */
  uint16_t hc = ((uint16_t)packet[10] << 8) + packet[11];
  //uint16_t hc_new = ~(~hc + ~m + m_new);
  uint16_t hc_new = hc + m + (~m_new + 1); // one's complement
  if (hc_new == 0xffff) hc_new ++; // solve corner case
  packet[10] = (hc_new >> 8);
  packet[11] = (hc_new & 0xff);
  return true;
}
