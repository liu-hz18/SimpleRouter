#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stack>
#include <assert.h>
#include <arpa/inet.h>

#define MAX_TABLE_SIZE 3000

RoutingTableEntry RoutingTable[MAX_TABLE_SIZE];
size_t current_size = 0;
size_t dfs_index = 0;
bool changed = false;
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
    uint32_t metric;   // 大端序
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

struct RouteEntryNode {
    RouteEntryNode* father;
    RouteEntryNode* left_child;
    RouteEntryNode* right_child;
    bool valid; // is routing entry
    RoutingTableEntry entry;
    RouteEntryNode() {
        father = left_child = right_child = nullptr;
        valid = false;
    }
};

RouteEntryNode* root = new RouteEntryNode();

void dfs(RouteEntryNode* cur_node) {
    if (cur_node->valid) {
        RoutingTable[dfs_index++] = cur_node->entry; 
    }
    if (cur_node->left_child != nullptr) {
        dfs(cur_node->left_child);
    } 
    if (cur_node->right_child != nullptr) {
        dfs(cur_node->right_child);
    }
}

void update_routing_table () {
    printf("!!!update cached routing table...\n");
    dfs_index = 0;
    dfs(root);
    assert (dfs_index == current_size);
}

void _insert(RoutingTableEntry entry) {
    entry.addr = entry.addr & 0xFFFFFFFF;
    RouteEntryNode* cur_node = root;
    uint32_t flag_mask = 0x80000000;
    uint32_t len = entry.len;
    uint32_t addr = ntohl(entry.addr);
    for (int i = 0; i < len; i++) {
        bool direction = flag_mask & addr;
        flag_mask >>= 1;
        if (direction) { // 1 is right
            if (cur_node->right_child == nullptr) {
                cur_node->right_child = new RouteEntryNode();
                cur_node->right_child->father = cur_node;
            }
            cur_node = cur_node->right_child;
        } else { // 0 is left
            if (cur_node->left_child == nullptr) {
                cur_node->left_child = new RouteEntryNode();
                cur_node->left_child->father = cur_node;
            }
            cur_node = cur_node->left_child;
        }
    }
    // init valid node
    if (!cur_node->valid) {
        current_size ++;
        cur_node->valid = true;
        cur_node->entry = entry;
        changed = true;
    } else {
        if (cur_node->entry.nexthop == entry.nexthop) {
            if (cur_node->entry.if_index != entry.if_index || cur_node->entry.metric != entry.metric) {
                cur_node->entry.if_index = entry.if_index;
                cur_node->entry.metric = entry.metric;
                changed = true;
            }
        } else if (cur_node->entry.metric > entry.metric) {
            cur_node->entry.nexthop = entry.nexthop;
            cur_node->entry.if_index = entry.if_index;
            cur_node->entry.metric = entry.metric;
            changed = true;
        }
    }
}

void _delete(RoutingTableEntry entry) {
    RouteEntryNode* cur_node = root;
    uint32_t flag_mask = 0x80000000;
    uint32_t len = entry.len;
    uint32_t addr = ntohl(entry.addr);
    for (int i = 0; i < len; i++) {
        bool direction = flag_mask & addr;
        flag_mask >>= 1;
        if (direction) {
            if (cur_node->right_child == nullptr) return;
            else cur_node = cur_node->right_child;
        } else {
            if (cur_node->left_child == nullptr) return;
            else cur_node = cur_node->left_child;
        }
    }
    // find the entry, delete and trace back
    RouteEntryNode* father = cur_node->father;
    current_size --;
    int height = len-1;
    while(father != nullptr) {
        if (cur_node->left_child != nullptr || cur_node->right_child != nullptr) {
            cur_node->valid = false; // lazy-remove
            break;
        }
        if (cur_node->valid && height != len-1) break;
        if (cur_node == cur_node->father->left_child) {
            cur_node = cur_node->father;
            father = cur_node->father;
            delete cur_node->left_child;
            cur_node->left_child = nullptr;
        } else {
            cur_node = cur_node->father;
            father = cur_node->father;
            delete cur_node->right_child;
            cur_node->right_child = nullptr;
        }
        height --;
    }
    changed = true;
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
    *nexthop = 0;
    *if_index = 0;
    RouteEntryNode* cur_node = root;
    uint32_t flag_mask = 0x80000000;
    std::stack<RouteEntryNode*> node_trace_stack;
    addr = ntohl(addr);
    for (int i = 0; i < 32; i ++) {
        bool direction = flag_mask & addr;
        flag_mask >>= 1;
        if (direction) {
            if (cur_node->right_child == nullptr) {
                if (cur_node -> valid) {
                    *nexthop = cur_node->entry.nexthop;
                    *if_index = cur_node->entry.if_index;
                    return true;
                }
                if (!node_trace_stack.empty()){
                    *nexthop = node_trace_stack.top()->entry.nexthop;
                    *if_index = node_trace_stack.top()->entry.if_index;
                    return true;
                }
                return false;
            } else {
                cur_node = cur_node->right_child;
                if (cur_node->valid) node_trace_stack.push(cur_node);
            }
        } else {
            if (cur_node->left_child == nullptr) {
                if (cur_node -> valid) {
                    *nexthop = cur_node->entry.nexthop;
                    *if_index = cur_node->entry.if_index;
                    return true;
                }
                if (!node_trace_stack.empty()){
                    *nexthop = node_trace_stack.top()->entry.nexthop;
                    *if_index = node_trace_stack.top()->entry.if_index;
                    return true;
                }
                return false;
            } else {
                cur_node = cur_node->left_child;
                if (cur_node->valid) node_trace_stack.push(cur_node);
            }
        }
    }
    // visit leaf node
    *nexthop = cur_node->entry.nexthop;
    *if_index = cur_node->entry.if_index;
    return true;
}
