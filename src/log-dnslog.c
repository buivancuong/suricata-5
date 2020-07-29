//
// Created by cuongbv on 29/07/2020.
//

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "util-print.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "output.h"
#include "log-dnslog.h"
#include "app-layer-dns-common.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "dns.log"
#define MODULE_NAME "LogDnsLog"
#define OUTPUT_BUFFER_SIZE 65535
#define QUERY 0
static const char* dns_log_enabled = NULL;

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>


#define LINE_SIZE 512
#define DOMAIN_NAME_SIZE 256
#define DOMAIN_ARRAY_SIZE 1024000




static char domainArray[DOMAIN_ARRAY_SIZE][DOMAIN_NAME_SIZE];

static void loadDomain(void) {
    static int loaded = 0;
    if(loaded == 1) {
        return;
    }
    char* line = NULL;
    char domain[DOMAIN_NAME_SIZE];
    char type[LINE_SIZE - DOMAIN_NAME_SIZE];
    unsigned int i = 0;
    FILE *pFile = fopen("/etc/saids/idsconfig/domains.lst", "r");
    size_t len = 0;

    while (getline(&line, &len, pFile) != -1) {
        memset(domain, '\0', DOMAIN_NAME_SIZE);
        memset(type, '\0', DOMAIN_NAME_SIZE);
        sscanf(line, "%[^,],%s", domain, type);
        strncpy(domainArray[i], domain, DOMAIN_NAME_SIZE);
        // printf("%s - %s\n", domain, type);
        i++;
    }
    fclose(pFile);
    printf("%s:%d Domain list: %d\n", __FILE__, __LINE__, i);
    loaded = 1;
}

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */

typedef struct LogDnsFileCtx_
{
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogDnsFileCtx;

typedef struct LogDnsLogThread_
{
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

static void LogQuery(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSQueryEntry *entry)
{
    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS request and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);

    /* time & tx */
    MemBufferWriteString(aft->buffer,
                         "%s [**] Query TX %04x [**] ", timebuf, tx->tx_id);

    /* query */
    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                   (uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)),
                   entry->len);

    char record[16] = "";
    DNSCreateTypeString(entry->type, record, sizeof(record));
    MemBufferWriteString(aft->buffer,
                         " [**] %s [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
                         record, srcip, sp, dstip, dp);

    char domain[DOMAIN_NAME_SIZE];
    uint32_t nOffset = 0;
    PrintRawUriBuf(domain, &nOffset, 256, (uint8_t*)((uint8_t*)entry + sizeof(DNSQueryEntry)), entry->len);
    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                   (uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)),
                   entry->len);
    domain[nOffset] = '\0';

    char srcport[32];
    sprintf(srcport, "%d", sp);

    // if (bf_has(filter, domain, strlen(domain)))
    // {
    //     FILE* fp = fopen("/var/log/ids/dnscheck.log","a+");
    //     fprintf(fp, "%s %s %s\n", srcip, srcport, domain);
    //     fclose(fp);
    // }

    if(!strcmp(dns_log_enabled, "yes"))
    {
        SCMutexLock(&hlog->file_ctx->fp_mutex);
        hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
                              MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
        SCMutexUnlock(&hlog->file_ctx->fp_mutex);
    }
}

static void LogAnswer(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSAnswerEntry *entry)
{
    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS response and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);
    /* time & tx*/
    MemBufferWriteString(aft->buffer,
                         "%s [**] Response TX %04x [**] ", timebuf, tx->tx_id);

    if (entry == NULL) {
        if (tx->rcode) {
            char rcode[16] = "";
            DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
            MemBufferWriteString(aft->buffer, "%s", rcode);
        } else if (tx->recursion_desired) {
            MemBufferWriteString(aft->buffer, "Recursion Desired");
        }
    } else {
        /* query */
        if (entry->fqdn_len > 0) {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                           (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                           entry->fqdn_len);
        } else {
            MemBufferWriteString(aft->buffer, "<no data>");
        }

        char record[16] = "";
        DNSCreateTypeString(entry->type, record, sizeof(record));
        MemBufferWriteString(aft->buffer,
                             " [**] %s [**] TTL %u [**] ", record, entry->ttl);

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry) + entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A)
        {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->type == DNS_RECORD_TYPE_AAAA)
        {
            char a[46];
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->data_len == 0)
        {
            MemBufferWriteString(aft->buffer, "<no data>");
        } else
        {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                           aft->buffer->size, ptr, entry->data_len);
        }
    }

    /* ip/tcp header info */
    MemBufferWriteString(aft->buffer,
                         " [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
                         srcip, sp, dstip, dp);

    if(!strcmp(dns_log_enabled, "yes")) {
        SCMutexLock(&hlog->file_ctx->fp_mutex);
        hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
                              MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
        SCMutexUnlock(&hlog->file_ctx->fp_mutex);
    }
}

static int LogDnsLogger(ThreadVars *tv, void *data, const Packet *p, Flow *f,
                        void *state, void *tx, uint64_t tx_id, uint8_t direction)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    int ipproto = 0;
    if (PKT_IS_IPV4(p))
        ipproto = AF_INET;
    else if (PKT_IS_IPV6(p))
        ipproto = AF_INET6;

    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }

    if (direction == STREAM_TOSERVER) {
        DNSQueryEntry *query = NULL;
        TAILQ_FOREACH(query, &dns_tx->query_list, next) {
            LogQuery(aft, timebuf, dstip, srcip, dp, sp, dns_tx, query);
        }
    } else if (direction == STREAM_TOCLIENT) {
        if (dns_tx->rcode)
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, NULL);
        if (dns_tx->recursion_desired)
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, NULL);

        DNSAnswerEntry *entry = NULL;
        TAILQ_FOREACH(entry, &dns_tx->answer_list, next) {
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, entry);
        }

        entry = NULL;
        TAILQ_FOREACH(entry, &dns_tx->authority_list, next) {
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, entry);
        }
    }

    aft->dns_cnt++;
    end:
    return 0;
}

static int LogDnsRequestLogger(ThreadVars *tv, void *data, const Packet *p, Flow *f,
                               void *state, void *tx, uint64_t tx_id)
{
    return LogDnsLogger(tv, data, p, f, state, tx, tx_id, STREAM_TOSERVER);
}

static int LogDnsResponseLogger(ThreadVars *tv, void *data, const Packet *p, Flow *f,
                                void *state, void *tx, uint64_t tx_id)
{
    return LogDnsLogger(tv, data, p, f, state, tx, tx_id, STREAM_TOCLIENT);
}

static TmEcode LogDnsLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogDnsLogThread *aft = SCMalloc(sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogDnsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for LogDNSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->dnslog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    loadDomain();
    return TM_ECODE_OK;
}

static TmEcode LogDnsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogDnsLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("DNS logger logged %" PRIu32 " transactions", aft->dns_cnt);
}

static void LogDnsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    LogFileFreeCtx(dnslog_ctx->file_ctx);
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogDnsLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(dnslog_ctx);
        return NULL;
    }
    dns_log_enabled = ConfNodeLookupChildValue(conf, "dnslogenabled");
    printf("%s:%d Write to dns.log: %s\n", __FILE__, __LINE__, dns_log_enabled);

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtx;

    SCLogDebug("DNS log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    return output_ctx;
}

void LogDnsLogRegister (void)
{
#ifndef HAVE_RUST
    /* Request logger. */
    OutputRegisterTxModuleWithProgress(LOGGER_DNS_TS, MODULE_NAME, "dns-log",
                                       LogDnsLogInitCtx, ALPROTO_DNS, LogDnsRequestLogger, 0, 1,
                                       LogDnsLogThreadInit, LogDnsLogThreadDeinit, LogDnsLogExitPrintStats);

    /* Response logger. */
    OutputRegisterTxModuleWithProgress(LOGGER_DNS_TC, MODULE_NAME, "dns-log",
                                       LogDnsLogInitCtx, ALPROTO_DNS, LogDnsResponseLogger, 1, 1,
                                       LogDnsLogThreadInit, LogDnsLogThreadDeinit, LogDnsLogExitPrintStats);

    /* enable the logger for the app layer */
    SCLogDebug("registered %s", MODULE_NAME);
#endif /* !HAVE_RUST */
}

