//
// Created by cuongbv on 29/07/2020.
//

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "bloom_filter.h"

filternode* pBloomFilterHead = NULL;
filternode* pBloomFilterTail = NULL;

char* trim_whitespace(char* str) {
    if(str == NULL || strlen(str) == 0) {
        return str;
    }
    int len = strlen(str);
    int j = 0;
    for(int i = 0; i < len; ++i) {
        if(isspace(str[i]) == 0) {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
    return str;
}

void reset(filternode* pTemp) {
    memset(pTemp->iphash, 0, sizeof(pTemp->iphash));
}

void load_bloom_filter(char* file_name) {
    if(file_name == NULL || strlen(file_name) == 0) {
        return;
    }
    FILE* pFile = fopen(file_name, "r");
    if(pFile == NULL) {
        return;
    }
    char line[512];
    char* lineDelim = "-";

    while(fgets(line, 512, pFile) != NULL) {
        //printf("%s:%s:%d line %s\n", __FILE__, __FUNCTION__, __LINE__, line);
        char* ip = strtok(line, lineDelim);
        char* filter_name = strtok(NULL, lineDelim);
        ip = trim_whitespace(ip);
        filter_name = trim_whitespace(filter_name);
        //printf("%s:%s:%d ip %s and filter_name %s\n", __FILE__, __FUNCTION__, __LINE__, ip, filter_name);
        add_entry(ip, filter_name);
        line[0] = '\0';
    }

    fclose(pFile);
}

void add_entry(char* ip, char* filter_name) {
    filternode* pNode = is_filter_exist(filter_name, &pBloomFilterHead);
    if(pNode == NULL) {
        pNode = add_filter(filter_name, &pBloomFilterHead, &pBloomFilterTail);
    }
    add_ip(pNode, ip);
}

filternode* is_filter_exist(char* filter_name, filternode** pBloomFilterHead) {
    //printf("filter_name %s and head %p\n", filter_name, *pBloomFilterHead);
    if(filter_name == NULL || strlen(filter_name) == 0) {
        return NULL;
    }

    filternode *pTempNode = *pBloomFilterHead;
    if(pTempNode == NULL) {
        return NULL;
    }
    while(pTempNode != NULL) {
        //printf("node filter %s\n", pTempNode->bloom_filter_name);
        if(!strcmp(filter_name, pTempNode->bloom_filter_name)) {
            //printf("node return %p\n", pTempNode);
            return pTempNode;
        }
        pTempNode = pTempNode->pNext;
    }
    return NULL;
}

filternode* add_filter(char *filter_name, filternode** pBloomFilterHead, filternode** pBloomFilterTail) {
    filternode *pTemp = (filternode *)malloc(sizeof(filternode));
    pTemp->pNext    = NULL;
    pTemp->pHead    = NULL;
    pTemp->pTail    = NULL;

    strcpy(pTemp->bloom_filter_name, filter_name);
    reset(pTemp);
    if(*pBloomFilterHead == NULL) {
        *pBloomFilterHead = *pBloomFilterTail = pTemp;
    } else {
        (*pBloomFilterTail)->pNext = pTemp;
        *pBloomFilterTail = pTemp;
    }
    return pTemp;
}

void delete_bloom_filters(filternode** pBloomFilterHead, filternode** pBloomFilterTail) {
    if((*pBloomFilterHead) == NULL) {
        return;
    }
    while(*pBloomFilterHead != *pBloomFilterTail) {
        filternode* pTemp = *pBloomFilterHead;
        *pBloomFilterHead          = (*pBloomFilterHead)->pNext;
        free(pTemp);
    }
    free(*pBloomFilterTail);
    *pBloomFilterHead = *pBloomFilterTail = NULL;
}

int check_ip(filternode* pNode, char* charIP) {
    if(charIP == NULL || (strlen(charIP) == 0) || pNode == NULL) {
        return 0;
    }
    char ip[32];
    strcpy(ip, charIP);
    //printf("%s:%s:%d ip %s\n", __FILE__, __FUNCTION__, __LINE__, charIP);
    char* ipDelim = ".";
    char* ipPart1 = strtok(ip, ipDelim);
    char* ipPart2 = strtok(NULL, ipDelim);
    char* ipPart3 = strtok(NULL, ipDelim);
    char* ipPart4 = strtok(NULL, ipDelim);
    uint8_t part1 = atoi(ipPart1);
    uint8_t part2 = atoi(ipPart2);
    uint8_t part3 = atoi(ipPart3);
    uint8_t part4 = atoi(ipPart4);
    uint32_t ipInt = ((uint32_t)part1) << 24
                     | ((uint32_t)part2) << 16
                     | ((uint32_t)part3) << 8
                     | ((uint32_t)part4);
    uint32_t ipNum = ipInt;
    for(uint8_t i = 0; i < 14; ++i) {
        if(get_bit(pNode->iphash, get_hash(ipInt, i)) == 0) {
            return 0;
        }
    }

    ipInt = reverse_bits(ipInt);

    for(uint8_t i = 0; i < 14; ++i) {
        if(get_bit(pNode->iprevhash, get_hash(ipInt, i)) == 0) {
            return 0;
        }
    }

    IpNode* pTemp = pNode->pHead;
    for(;pTemp != NULL;pTemp = pTemp->pNext) {
        if(pTemp->ipNum == ipNum) {
            return 1;
        }
    }
    return 0;
}

void set_bit(uint32_t* iphash, uint32_t index) {
    uint32_t hash_index = index / 32;
    uint8_t hash_offset = index % 32;
    //printf("%s:%s:%d ip %d %d %d\n", __FILE__, __FUNCTION__, __LINE__, index, hash_index, hash_offset);
    iphash[hash_index] |= (0x1 << hash_offset);
}

uint32_t  get_bit(uint32_t* iphash, uint32_t index) {
    uint32_t hash_index = index / 32;
    uint8_t hash_offset = index % 32;
    return (iphash[hash_index]  << (31 - hash_offset)) >> 31;
}

uint32_t get_hash(uint32_t ipInt, uint8_t part) {
    uint32_t hash_num = ~0;
    uint32_t mask = (hash_num << 13) >> part;
    uint32_t val = (ipInt & mask) >> (13 - part);
    //printf("%s ip %u part %u and val %u\n", __FUNCTION__, ipInt, part, val);
    return val;
}

uint32_t bitswap(uint32_t num, uint8_t i, uint8_t j) {
    //printf("num %u\n", num);
    uint32_t i_mask = 0x1 << i;
    uint32_t j_mask = 0x1 << j;
    uint32_t i_bit  = num & i_mask;
    uint32_t j_bit  = num & j_mask;
    num             = num & (~i_mask) & (~j_mask);
    i_bit           = i_bit <<  (j -i);
    j_bit           = j_bit >>  (j -i);
    uint32_t val =  (num | i_bit | j_bit);
    //printf("result %u, ith %u and jth %u\n", val, i, j);
    return val;
}

uint32_t reverse_bits(uint32_t num) {
    //printf("Initial num %u\n", num);
    for(uint8_t i = 0; i < 16; ++i) {
        num = bitswap(num, i, 31 - i);
    }
    //printf("reverse num %u\n", num);
    return num;
}

void add_ip(filternode* pNode, char* charIP) {
    if(charIP == NULL || (strlen(charIP) == 0)) {
        return;
    }
    //printf("%s:%s:%d ip %s\n", __FILE__, __FUNCTION__, __LINE__, charIP);
    char* ipDelim = ".";
    char* ipPart1 = strtok(charIP, ipDelim);
    char* ipPart2 = strtok(NULL, ipDelim);
    char* ipPart3 = strtok(NULL, ipDelim);
    char* ipPart4 = strtok(NULL, ipDelim);
    uint8_t part1 = atoi(ipPart1);
    uint8_t part2 = atoi(ipPart2);
    uint8_t part3 = atoi(ipPart3);
    uint8_t part4 = atoi(ipPart4);
    uint32_t ipInt = ((uint32_t)part1) << 24
                     | ((uint32_t)part2) << 16
                     | ((uint32_t)part3) << 8
                     | ((uint32_t)part4);
    IpNode* ipNode  = (IpNode *)malloc(sizeof(IpNode));
    ipNode->ipNum   = ipInt;
    ipNode->pNext = NULL;

    if(pNode->pHead == NULL && pNode->pTail == NULL) {
        pNode->pHead = pNode->pTail = ipNode;
    } else {
        pNode->pTail->pNext = ipNode;
        pNode->pTail        = pNode->pTail->pNext;
    }
    //printf("%s:%s:%d ip %s %u\n", __FILE__, __FUNCTION__, __LINE__, charIP, ipInt);
    for(uint8_t i = 0; i < 14; ++i) {
        set_bit(pNode->iphash, get_hash(ipInt, i));
    }
    ipInt = reverse_bits(ipInt);
    for(uint8_t i = 0; i < 14; ++i) {
        set_bit(pNode->iprevhash, get_hash(ipInt, i));
    }
    //printf("%s:%s:%d ip %d %d %d %d\n", __FILE__, __FUNCTION__, __LINE__, part1, part2, part3, part4);
    //printf("%s:%s:%d ip %d %d %d %d %d %d\n", __FILE__, __FUNCTION__, __LINE__, bhash1, bhash2, bhash3, bhash4, bhash5, bhash6);
}
