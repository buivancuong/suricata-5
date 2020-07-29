//
// Created by cuongbv on 29/07/2020.
//

#include <string.h>
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"
#include "util-print.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-src.h"
#include "util-proto-name.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectSrcSetup(DetectEngineCtx *, Signature *, char *);
static int DetectSrcMatch(ThreadVars *, DetectEngineThreadCtx *,
                          Packet *, Signature *, SigMatch *);
static void DetectSrcRegisterTests(void);
static void DetectSrcFree(void *);

typedef struct _linknode {
    struct _linknode *pNext;
    char   ip[46];
    int id;
}linknode;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int IsDataExist(char* ip, int id, linknode** pHead) {
    pthread_mutex_lock(&mutex);
    //printf("[%d:%s] %s and id %d and header %p\n", pthread_self(), __FUNCTION__, ip, id, *pHead);
    linknode *pTempNode = *pHead;
    if(pTempNode == NULL) {
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    while(pTempNode != NULL) {
        if(!strcmp(ip, pTempNode->ip) && pTempNode->id == id) {
            pthread_mutex_unlock(&mutex);
            return 1;
        }
        pTempNode = pTempNode->pNext;
    }
    pthread_mutex_unlock(&mutex);
    return 0;
}

static void addData(char *ip, int id, linknode** pHead, linknode** pTail) {
    pthread_mutex_lock(&mutex);
    linknode *pTemp = (linknode *)malloc(sizeof(linknode));
    pTemp->pNext    = NULL;
    strcpy(pTemp->ip, ip);
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

void DetectSrcRegister(void) {
    //printf("[%d:%s] %s:%d \n",pthread_self(), __FUNCTION__, __FILE__, __LINE__);
    //fflush(stdout);
    sigmatch_table[DETECT_SRC].name = "blocksrcip";
    sigmatch_table[DETECT_SRC].desc = "check for a specific TCP sequence number";
    sigmatch_table[DETECT_SRC].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#seq";
    sigmatch_table[DETECT_SRC].Match = DetectSrcMatch;
    sigmatch_table[DETECT_SRC].Setup = DetectSrcSetup;
    sigmatch_table[DETECT_SRC].Free = DetectSrcFree;
    sigmatch_table[DETECT_SRC].RegisterTests = NULL;
}

/**
 * \internal
 * \brief This function is used to match packets with a given Seq number
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSrcData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectSrcMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
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
    if(diff > 10.00) {
        //reset data
        //printf("[MQ_SEND]%s data reset\n", __FUNCTION__);
        start_t = (time_t)-1;
        DeleteData(&pHead, &pTail);
    }
    DetectSrcData *data = (DetectSrcData *)(s->sm_lists_tail[DETECT_SM_LIST_MATCH]->ctx);
    //printf("[%d:%s]  Check Packet type %p and text %s\n", pthread_self(), __FUNCTION__, data, data->text);
    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }
    if ( !( PKT_IS_TCP(p) || PKT_IS_UDP(p) ) ) {
        return 0;
    }
    //printf("[%s]  Before getting ip address\n", __FUNCTION__);
    //fflush(stdout);
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    if(IsDataExist(srcip, s->id, &pHead)) {
        //printf("[MQ_SEND]:%d:%s Duplicate ip %s detected\n", pthread_self(), __FUNCTION__, srcip);
        //fflush(stdout);
        return 1;
    }else {
        //printf("[MQ_SEND]%d:%s ip %s added\n", pthread_self(), __FUNCTION__, srcip);
        //fflush(stdout);
        addData(srcip, s->id, &pHead, &pTail);
    }
    //printf("[%s]  Before sending data and buffer size %d and data %p and data text %p\n", __FUNCTION__, MQ_TEXT_LENGTH, data, data->text);
    //printf("[%s]  %p\n", __FUNCTION__, data->text);
    //printf("[%s]  %s\n", __FUNCTION__, data->text);
    //fflush(stdout);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,"%s",data->text);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",srcip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",s->id);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",dstip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",getpid());
    //printf("[MQ_SEND] sending message %s and length %d and priority %d\n", buffer, cx, 1);
    //fflush(stdout);
    mq_send(g_mqd,buffer,cx,1);
    return 1;
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
static int DetectSrcSetup (DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    printf("[%s] %s:%d and optstr %s\n",__FUNCTION__, __FILE__, __LINE__, optstr);
    fflush(stdout);
    DetectSrcData *data = NULL;
    SigMatch *sm = NULL;

    data = SCMalloc(sizeof(DetectSrcData));
    if (unlikely(data == NULL))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_SRC;

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
static void DetectSrcFree(void *ptr)
{
    //printf("[%s] %s:%d \n",__FUNCTION__, __FILE__, __LINE__);
    //fflush(stdout);
    DetectSrcData *data = (DetectSrcData *)ptr;
    SCFree(data);
}


#ifdef UNITTESTS

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectSrc
 */
static void DetectSrcRegisterTests(void)
{
#ifdef UNITTESTS
    //    UtRegisterTest("DetectSrcSigTest01", DetectSrcSigTest01, 1);
//    UtRegisterTest("DetectSrcSigTest02", DetectSrcSigTest02, 1);
#endif /* UNITTESTS */
}

