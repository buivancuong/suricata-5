//
// Created by cuongbv on 29/07/2020.
//

#include <string.h>
#include <time.h>
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"
#include "util-print.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "checktime.h"
#include "util-proto-name.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int CheckTimeSetup(DetectEngineCtx *, Signature *, char *);
static int CheckTimeMatch(ThreadVars *, DetectEngineThreadCtx *,
                          Packet *, Signature *, SigMatch *);
static void CheckTimeRegsiterTests(void);
static void CheckTimeFree(void *);

typedef struct _linknode {
    struct _linknode *pNext;
    char   srcip[46];
    char   dstip[46];
    int id;
}linknode;

typedef struct _timenode {
    char name[128];
    int day;
    struct tm start_time;
    struct tm end_time;
}timenode;

static timenode time_nodes[2];

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void store_hr_time(timenode* time_node, char* start_time, char* end_time, char* day) {
    char* delim = ":";
    char* hr = strtok(start_time, delim);
    char* min = strtok(NULL, delim);
    char* sec = strtok(NULL, delim);

    time_node->start_time.tm_hour = atoi(hr);
    time_node->start_time.tm_min = atoi(min);
    time_node->start_time.tm_sec = atoi(sec);
    time_node->start_time.tm_year = 2000;
    time_node->start_time.tm_mon = 0;
    time_node->start_time.tm_mday = 1;

    hr = strtok(end_time, delim);
    min = strtok(NULL, delim);
    sec = strtok(NULL, delim);
    time_node->end_time.tm_hour = atoi(hr);
    time_node->end_time.tm_min = atoi(min);
    time_node->end_time.tm_sec = atoi(sec);
    time_node->end_time.tm_year = 2000;
    time_node->end_time.tm_mon = 0;
    time_node->end_time.tm_mday = 1;
    time_node->day     = atoi(day);
}

int within_time_range(timenode* time_node, struct tm* packet_time) {
    if(time_node->day != 0) {
        if((time_node->day % 7) != packet_time->tm_wday) {
            return 0;
        }
    }
    packet_time->tm_year = 2000;
    packet_time->tm_mon = 0;
    packet_time->tm_mday = 1;
    packet_time->tm_wday = -1;
    packet_time->tm_yday = -1;
    packet_time->tm_isdst = -1;
    time_t start_time = mktime(&(time_node->start_time));
    time_t pkt_time = mktime(packet_time);
    time_t end_time = mktime(&(time_node->end_time));
    if(pkt_time >= start_time && pkt_time <= end_time) {
        return 1;
    }
    return 0;
}

void load_time_range() {
    FILE* pFile = fopen("/etc/saids/idsconfig/timerange.conf", "r");
    if(pFile == NULL) {
        return;
    }
    char line[512];
    char* lineDelim = " ";
    int i = 0;

    while(fgets(line, 512, pFile) != NULL) {
        char* node_name = strtok(line, lineDelim);
        strcpy(time_nodes[i].name, node_name);

        char* start_hr_time = strtok(NULL, lineDelim);
        char* end_hr_time = strtok(NULL, lineDelim);
        char* day_of_week = strtok(NULL, lineDelim);

        store_hr_time(&time_nodes[i], start_hr_time, end_hr_time, day_of_week);
        i++;
    }
    fclose(pFile);
}

static int IsDataExist(char* srcip, char* dstip, int id, linknode** pHead) {
    pthread_mutex_lock(&mutex);
    //printf("[%d:%s] %s and id %d and header %p\n", pthread_self(), __FUNCTION__, ip, id, *pHead);
    linknode *pTempNode = *pHead;
    if(pTempNode == NULL) {
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    while(pTempNode != NULL) {
        if(!strcmp(srcip, pTempNode->srcip) && !strcmp(dstip, pTempNode->dstip) &&pTempNode->id == id) {
            pthread_mutex_unlock(&mutex);
            return 1;
        }
        pTempNode = pTempNode->pNext;
    }
    pthread_mutex_unlock(&mutex);
    return 0;
}

static void addData(char *srcip, char* dstip, int id, linknode** pHead, linknode** pTail) {
    pthread_mutex_lock(&mutex);
    linknode *pTemp = (linknode *)malloc(sizeof(linknode));
    pTemp->pNext    = NULL;
    strcpy(pTemp->srcip, srcip);
    strcpy(pTemp->dstip, dstip);
    pTemp->id = id;
    if(*pHead == NULL) {
        *pHead = *pTail = pTemp;
    } else {
        (*pTail)->pNext = pTemp;
        *pTail = pTemp;
    }
    pthread_mutex_unlock(&mutex);
}

static void DeleteData(linknode** pHead, linknode** pTail) {
    pthread_mutex_lock(&mutex);
    if((*pHead) == NULL) {
        pthread_mutex_unlock(&mutex);
        return;
    }
    while(*pHead != *pTail) {
        linknode* pTemp = *pHead;
        *pHead          = (*pHead)->pNext;
        free(pTemp);
    }
    free(*pTail);
    *pHead = *pTail = NULL;
    pthread_mutex_unlock(&mutex);
}

void CheckTimeRegister(void) {
    //printf("[%d:%s] %s:%d \n",pthread_self(), __FUNCTION__, __FILE__, __LINE__);
    //fflush(stdout);
    sigmatch_table[CHECK_TIME].name = "checktime";
    sigmatch_table[CHECK_TIME].desc = "check time in range";
    sigmatch_table[CHECK_TIME].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#seq";
    sigmatch_table[CHECK_TIME].Match = CheckTimeMatch;
    sigmatch_table[CHECK_TIME].Setup = CheckTimeSetup;
    sigmatch_table[CHECK_TIME].Free = CheckTimeFree;
    sigmatch_table[CHECK_TIME].RegisterTests = NULL;
}

/**
 * \internal
 * \brief This function is used to match packets with a given Seq number
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into CheckTimeData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int CheckTimeMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                          Packet *p, Signature *s, SigMatch *m)
{
    //printf("[%d:%s] %s:%d \n",pthread_self(), __FUNCTION__, __FILE__, __LINE__);
    //fflush(stdout);
    char srcip[46];
    char dstip[46];
    char buffer[MQ_TEXT_LENGTH];
    int cx = 0;
    static linknode *pHead = NULL;
    static linknode *pTail = NULL;
    static time_t start_t = (time_t) -1;
    if(start_t == (time_t)-1) {
        time(&start_t);
    }
    time_t now;
    time(&now);
    double diff = difftime(now, start_t);
    //printf("[MQ_SEND]%s time duration %f\n", __FUNCTION__, diff);
    //if(diff > 10.00) {
    //reset data
    //printf("[MQ_SEND]%s data reset\n", __FUNCTION__);
    //   start_t = (time_t)-1;
    //   DeleteData(&pHead, &pTail);
    //}
    CheckTimeData *data = (CheckTimeData *)(s->sm_lists_tail[DETECT_SM_LIST_MATCH]->ctx);
    //printf("[MQ_SEND]%s and post detect data %p\n", __FUNCTION__, data);
    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }
    if ( !( PKT_IS_TCP(p) || PKT_IS_UDP(p) ) ) {
        return 0;
    }
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    //printf("[MQ_SEND]%s checking link list %d\n", __FUNCTION__, __LINE__);
    /*if(IsDataExist(srcip, dstip, s->id, &pHead)) {
      //printf("[MQ_SEND]:%d:%s Duplicate ip %s detected\n", pthread_self(), __FUNCTION__, srcip);
      //fflush(stdout);
      return 1;
    }else {
      //printf("[MQ_SEND]%d:%s ip %s adding\n", pthread_self(), __FUNCTION__, srcip);
      //fflush(stdout);
      addData(srcip, dstip, s->id, &pHead, &pTail);
      //printf("[MQ_SEND]%d:%s ip %s added\n", pthread_self(), __FUNCTION__, srcip);
    }*/
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,"%s",data->text);
    //printf("%s:%s:%d output to queue: %s\n", __FILE__, __FUNCTION__, __LINE__, data->text);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",srcip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",p->sp);
    //printf("%s:%s:%d output to queue: %s\n", __FILE__, __FUNCTION__, __LINE__, srcip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",dstip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",p->dp);
    //printf("%s:%s:%d output to queue: %s\n", __FILE__, __FUNCTION__, __LINE__, dstip);
    //printf("%s:%s:%d output to queue: %p\n", __FILE__, __FUNCTION__, __LINE__, s);
    //printf("%s:%s:%d output to queue: %d\n", __FILE__, __FUNCTION__, __LINE__, s->id);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",s->id);
    struct tm *packet_time = localtime(&(p->ts.tv_sec));
    //printf("%s:%s:%d output to queue: %s\n", __FILE__, __FUNCTION__, __LINE__, buffer);
    if(!strcmp(data->text, time_nodes[0].name)) {
        if(within_time_range(&time_nodes[0], packet_time) == 1) {
            //printf("%s:%s:%d matched rule: %s %ld, %ld, %ld\n", __FILE__, __FUNCTION__, __LINE__, data->text, (long)(time_nodes[0].start_timeval), p->ts.tv_sec, (long)(time_nodes[0].end_timeval));
            return 1;
        }
    } else if(!strcmp(data->text, time_nodes[1].name)) {
        if(within_time_range(&time_nodes[1], packet_time) == 1) {
            //printf("%s:%s:%d matched rule: %s %ld, %ld, %ld\n", __FILE__, __FUNCTION__, __LINE__, data->text, (long)(time_nodes[1].start_timeval), p->ts.tv_sec, (long)(time_nodes[1].end_timeval));
            return 1;
        }
    }
    //printf("return value 1\n");
    //mq_send(g_mqd,buffer,cx,3);
    return 0;
}

/**
 * \internal
 * \brief this function is used to add the seq option into the signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int CheckTimeSetup (DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    //printf("[%s] %s:%d and optstr %s\n",__FUNCTION__, __FILE__, __LINE__, optstr);
    //fflush(stdout);
    CheckTimeData *data = NULL;
    SigMatch *sm = NULL;

    data = SCMalloc(sizeof(CheckTimeData));
    if (unlikely(data == NULL))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = CHECK_TIME;

    //printf("[%s] %s:%p and data text%p\n",__FUNCTION__, __FILE__, data, data->text);
    memset(data->text, 0x00, MQ_TEXT_LENGTH);
    if (NULL == strncpy(data->text, optstr,MQ_TEXT_LENGTH)) {
        goto error;
    }
    sm->ctx = data;

    //printf("[%s] %s:%p and data text%s and ctx %p\n",__FUNCTION__, __FILE__, data->text, sm->ctx);
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

    error:
    if (data)
        SCFree(data);
    if (sm)
        SigMatchFree(sm);
    return -1;

}

/**
 * \internal
 * \brief this function will free memory associated with seq option
 *
 * \param data pointer to seq configuration data
 */
static void CheckTimeFree(void *ptr)
{
    //printf("[%s] %s:%d \n",__FUNCTION__, __FILE__, __LINE__);
    //fflush(stdout);
    CheckTimeData *data = (CheckTimeData *)ptr;
    SCFree(data);
}


#ifdef UNITTESTS

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for PostDetect
 */
static void CheckTimeRegsiterTests(void)
{
#ifdef UNITTESTS
    //    UtRegisterTest("PostDetectSigTest01", PostDetectSigTest01, 1);
//    UtRegisterTest("PostDetectSigTest02", PostDetectSigTest02, 1);
#endif /* UNITTESTS */
}