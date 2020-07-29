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

#include "detect-dst.h"
#include "util-proto-name.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectDstSetup(DetectEngineCtx *, Signature *, char *);
static int DetectDstMatch(ThreadVars *, DetectEngineThreadCtx *,
                          Packet *, Signature *, SigMatch *);
static void DetectDstRegisterTests(void);
static void DetectDstFree(void *);

typedef struct _linknode {
    struct _linknode *pNext;
    char ip[46];
    int id;
}linknode;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int IsDataExist(char* ip, int id, linknode** pHead) {
    pthread_mutex_lock(&mutex);
    linknode *pTemp = *pHead;
    if(pTemp == NULL) {
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    while(pTemp != NULL) {
        if(!strcmp(ip, pTemp->ip) && pTemp->id == id) {
            pthread_mutex_unlock(&mutex);
            return 1;
        }
        pTemp = pTemp->pNext;
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
        (*pHead)   = (*pHead)->pNext;
        free(pTemp);
    }
    free(*pTail);
    *pHead = *pTail = NULL;
    pthread_mutex_unlock(&mutex);
}

void DetectDstRegister(void) {
    sigmatch_table[DETECT_DST].name = "blockdstip";
    sigmatch_table[DETECT_DST].desc = "check for a specific TCP sequence number";
    sigmatch_table[DETECT_DST].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#seq";
    sigmatch_table[DETECT_DST].Match = DetectDstMatch;
    sigmatch_table[DETECT_DST].Setup = DetectDstSetup;
    sigmatch_table[DETECT_DST].Free = DetectDstFree;
    sigmatch_table[DETECT_DST].RegisterTests = NULL;
}

void without_comma(char* str) {
    if(str == NULL || strlen(str) == 0) {
        return;
    }
    //printf("Before Change %s\n", str);
    int str_len = strlen(str);
    for(int i = 0; i < str_len; ++i) {
        if(str[i] == ',') {
            str[i] = '-';
        }
    }
    //printf("After Change %s\n", str);
}
/**
 * \internal
 * \brief This function is used to match packets with a given Seq number
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectDstData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectDstMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                          Packet *p, Signature *s, SigMatch *m)
{
    char dstip[46];
    char srcip[46];
    char buffer[MQ_TEXT_LENGTH];
    int cx = 0;
    static linknode* pHead = NULL;
    static linknode* pTail = NULL;
    static time_t start_t = (time_t)-1;
    if(start_t == (time_t)-1) {
        time(&start_t);
    }
    time_t now;
    time(&now);
    double diff = difftime(now, start_t);
    if(diff > 10) {
        start_t = (time_t)-1;
        DeleteData(&pHead, &pTail);
    }
    DetectDstData *data = (DetectDstData *)(s->sm_lists_tail[DETECT_SM_LIST_MATCH]->ctx);
    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }
    if ( !( PKT_IS_TCP(p) || PKT_IS_UDP(p) ) ) {
        return 0;
    }
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
    if(IsDataExist(dstip, s->id, &pHead)) {
        return 1;
    } else {
        addData(dstip, s->id, &pHead, &pTail);
    }
    char text_msg[256];
    strcpy(text_msg, data->text);
    //without_comma(text_msg);

    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,"%s",text_msg);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",dstip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",s->id);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",srcip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",getpid());
    //printf("[MQ_SEND] sending message %s and length %d and priority %d\n", buffer, cx, 2);
    //fflush(stdout);
    mq_send(g_mqd,buffer,cx,2);
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
static int DetectDstSetup (DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    DetectDstData *data = NULL;
    SigMatch *sm = NULL;

    data = SCMalloc(sizeof(DetectDstData));
    if (unlikely(data == NULL))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DST;

    memset(data->text, 0x00, MQ_TEXT_LENGTH);
    if (NULL == strncpy(data->text, optstr,MQ_TEXT_LENGTH)) {
        goto error;
    }
    sm->ctx = data;

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
static void DetectDstFree(void *ptr)
{
    DetectDstData *data = (DetectDstData *)ptr;
    SCFree(data);
}


#ifdef UNITTESTS

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectDst
 */
static void DetectDstRegisterTests(void)
{
#ifdef UNITTESTS
    //    UtRegisterTest("DetectDstSigTest01", DetectDstSigTest01, 1);
//    UtRegisterTest("DetectDstSigTest02", DetectDstSigTest02, 1);
#endif /* UNITTESTS */
}
