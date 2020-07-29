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

#include "detect-conn.h"
#include "util-proto-name.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectConnSetup(DetectEngineCtx *, Signature *, char *);
static int DetectConnMatch(ThreadVars *, DetectEngineThreadCtx *,
                           Packet *, Signature *, SigMatch *);
static void DetectConnRegisterTests(void);
static void DetectConnFree(void *);


void DetectConnRegister(void) {
    sigmatch_table[DETECT_CONN].name = "blockconn";
    sigmatch_table[DETECT_CONN].desc = "check for a specific TCP sequence number";
    sigmatch_table[DETECT_CONN].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#seq";
    sigmatch_table[DETECT_CONN].Match = DetectConnMatch;
    sigmatch_table[DETECT_CONN].Setup = DetectConnSetup;
    sigmatch_table[DETECT_CONN].Free = DetectConnFree;
    sigmatch_table[DETECT_CONN].RegisterTests = DetectConnRegisterTests;
}

/**
 * \internal
 * \brief This function is used to match packets with a given Seq number
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectConnData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectConnMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Packet *p, Signature *s, SigMatch *m)
{
    char srcip[46], dstip[46];
    char proto[16];
    char buffer[MQ_TEXT_LENGTH];
    int cx = 0;
    DetectConnData *data = (DetectConnData *)(s->sm_lists_tail[DETECT_SM_LIST_MATCH]->ctx);
    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }
    if ( !( PKT_IS_TCP(p) || PKT_IS_UDP(p) ) ) {
        return 0;
    }
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
        strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
    }
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,"%s",srcip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",p->sp);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",dstip);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",p->dp);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",proto);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",s->id);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%s",data->text);
    cx += snprintf ( buffer+cx, MQ_TEXT_LENGTH-cx,",%d",getpid());
    //printf("[MQ_SEND] sending message %s and length %d and priority %d\n", buffer, cx, 0);
    //fflush(stdout);
    mq_send(g_mqd,buffer,cx,0);
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
static int DetectConnSetup (DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    //printf("%s:%s and optstr %s\n", __FILE__, __FUNCTION__, optstr);
    DetectConnData *data = NULL;
    SigMatch *sm = NULL;

    data = SCMalloc(sizeof(DetectConnData));
    if (unlikely(data == NULL))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_CONN;

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
static void DetectConnFree(void *ptr)
{
    DetectConnData *data = (DetectConnData *)ptr;
    SCFree(data);
}


#ifdef UNITTESTS

/**
 * \test DetectConnSigTest01 tests parses
 */
static int DetectConnSigTest01(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    /* These three are crammed in here as there is no Parse */
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing seq\";seq:foo;sid:1;)") != NULL)
    {
        printf("invalid seq accepted: ");
        goto cleanup;
    }
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing seq\";seq:9999999999;sid:1;)") != NULL)
    {
        printf("overflowing seq accepted: ");
        goto cleanup;
    }
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing seq\";seq:-100;sid:1;)") != NULL)
    {
        printf("negative seq accepted: ");
        goto cleanup;
    }
    result = 1;

cleanup:
    if (de_ctx) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
end:
    return result;
}

/**
 * \test DetectConnSigTest02 tests seq keyword
 */
static int DetectConnSigTest02(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[2] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_ICMP);
    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    /* TCP w/seq=42 */
    p[0]->tcph->th_seq = htonl(42);

    /* TCP w/seq=100 */
    p[1]->tcph->th_seq = htonl(100);

    char *sigs[2];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing seq\"; seq:41; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing seq\"; seq:42; sid:2;)";

    uint32_t sid[2] = {1, 2};

    uint32_t results[3][2] = {
                              /* packet 0 match sid 1 but should not match sid 2 */
                              {0, 1},
                              /* packet 1 should not match */
                              {0, 0},
                              /* packet 2 should not match */
                              {0, 0} };

    result = UTHGenericTest(p, 3, sigs, sid, (uint32_t *) results, 2);
    UTHFreePackets(p, 3);
end:
    return result;
}

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectConn
 */
static void DetectConnRegisterTests(void)
{
#ifdef UNITTESTS
    //    UtRegisterTest("DetectConnSigTest01", DetectConnSigTest01, 1);
//    UtRegisterTest("DetectConnSigTest02", DetectConnSigTest02, 1);
#endif /* UNITTESTS */
}

