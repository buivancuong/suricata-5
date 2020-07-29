//
// Created by cuongbv on 29/07/2020.
//

#ifndef SURICATA_5_0_3_BLOOM_FILTER_H
#define SURICATA_5_0_3_BLOOM_FILTER_H

#include <stdio.h>
#include <stdint.h>

typedef struct _ipnode {
    struct _ipnode *pNext;
    uint32_t ipNum;
}IpNode;

typedef struct _bloom_filter_node {
    struct _bloom_filter_node *pNext;
    uint32_t iphash[32*1024];
    uint32_t iprevhash[32*1024];
    char bloom_filter_name[512];
    IpNode *pHead;
    IpNode *pTail;
}filternode;

uint32_t reverse_bits(uint32_t num);
uint32_t bitswap(uint32_t num, uint8_t i, uint8_t j);
uint32_t get_hash(uint32_t ipInt, uint8_t part);
void reset(filternode* pTemp);
int check_ip(filternode* pNode, char* charIP);
void add_ip(filternode* pNode, char* charIP);
filternode* is_filter_exist(char* filter_name, filternode** pHead);
filternode* add_filter(char *filter_name, filternode** pHead, filternode** pTail);
void delete_bloom_filters(filternode** pHead, filternode** pTail);
void load_bloom_filter(char* file_name);
char* trim_whitespace(char*);
void add_entry(char* ip, char* filter_name);
void set_bit(uint32_t* iphash, uint32_t index);
uint32_t  get_bit(uint32_t* iphash, uint32_t index);

#endif //SURICATA_5_0_3_BLOOM_FILTER_H
