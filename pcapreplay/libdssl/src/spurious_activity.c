#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <pthread.h>
#include <glib-2.0/glib.h>

#include "stdinc.h"
#include "capenv.h"
#include "session.h"
#include "spurious_activity.h"


static MonitorSpActivityConf g_monitor_sp_activity_conf;

static GHashTable* g_tcp_half_open_ht = NULL;
static GAsyncQueue* g_tcp_half_open_qu = NULL;

static uint32_t g_tcp_half_open_qu_size = 0;
static uint32_t g_tcp_half_open_ht_size = 0;
static uint32_t g_num_of_embryonic_conn_detected = 0;

static pthread_t g_tcp_half_open_ht_tid;
static pthread_t g_tcp_half_open_qu_tid;
static pthread_mutex_t g_tcp_half_open_ht_lock;   
static pthread_cond_t g_tcp_half_open_cond;

static int g_sp_activity_monitor_initialized = 0;
static int g_end_is_nigh = 0;


static void GetTcpHalfOpenKeyHash(TcpHalfOpen* tcp_half_open, char* key, size_t key_len);
static void InitTcpHalfOpenEntry(TcpSession* sess, int action, TcpHalfOpen* tcp_half_open); 
static char* TcpHalfOpenEntryToString(TcpHalfOpen* tcp_half_open, char* buff, size_t buff_len);

static void _FreeTcpHalfOpenEntry(gpointer data) {
    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif

    DEBUG_TRACE("SpAM: Free tcp half open entry: %s",
                TcpHalfOpenEntryToString((TcpHalfOpen*)data, buff, sizeof(buff)));
    free(data);
}

static int _AddTcpHalfOpenEntry(TcpHalfOpen* tcp_half_open) {
    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif

    char* key = NULL;
    TcpHalfOpen* tmp_tcp_half_open = NULL; 
    gboolean found = FALSE;

    if ( !tcp_half_open ) { 
        return SA_ERROR;
    }

    found = g_hash_table_lookup_extended(g_tcp_half_open_ht,
                                         tcp_half_open->key_hash,
                                         (gpointer*) &key,
                                         (gpointer*) &tmp_tcp_half_open);

    if ( found == TRUE ) {
        tmp_tcp_half_open->count++;

        DEBUG_TRACE("SpAM: Existing half open entry: %s, lookup table size: %u",
                    TcpHalfOpenEntryToString(tmp_tcp_half_open, buff, sizeof(buff)),
                    g_hash_table_size(g_tcp_half_open_ht));

        free(tcp_half_open);
        return SA_OK;
    }

    key = (char*) calloc(TCP_HALF_OPEN_KEY_MAX_LEN, sizeof(char));
    snprintf(key, TCP_HALF_OPEN_KEY_MAX_LEN, "%s", tcp_half_open->key_hash);

    g_hash_table_insert(g_tcp_half_open_ht,
                        (gpointer) key,
                        (gpointer) tcp_half_open); 

    g_tcp_half_open_ht_size++;

    DEBUG_TRACE("SpAM: Added tcp half open entry: %s, lookup table size: %u",
                TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)),
                g_hash_table_size(g_tcp_half_open_ht));

    return SA_OK;
}

static int _DeleteTcpHalfOpenEntry(TcpHalfOpen* tcp_half_open) {
    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif

    if ( !tcp_half_open ) { 
        return SA_ERROR;
    }

    DEBUG_TRACE("SpAM: Deleting half open entry: %s",
                TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)));

    if ( g_hash_table_remove(g_tcp_half_open_ht, tcp_half_open->key_hash) == TRUE ) {
        g_tcp_half_open_ht_size--;
    }

    return SA_OK;
}

static void GetTcpHalfOpenKeyHash(TcpHalfOpen* tcp_half_open, char* key, size_t key_len) {
    char server[42] = {0,};
    char client[42] = {0,};

    if ( ( !tcp_half_open ) || ( !key ) ||  ( key_len == 0 ) ) {
        return;
    }

    AddressToString(tcp_half_open->server_ip, tcp_half_open->server_port, server );
    AddressToString(tcp_half_open->client_ip, tcp_half_open->client_port, client );

    snprintf(key, key_len, "%s<->%s", server, client);  
}

static void InitTcpHalfOpenEntry(TcpSession* sess, int action, TcpHalfOpen* tcp_half_open) {
    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif

    if ( ( !sess ) || ( !tcp_half_open ) ) {
        return;
    }

    tcp_half_open->server_ip = sess->serverStream.ip_addr;
    tcp_half_open->client_ip = sess->clientStream.ip_addr;
    tcp_half_open->server_port = sess->serverStream.port; 
    tcp_half_open->client_port = sess->clientStream.port; 
    tcp_half_open->count = 1;
    tcp_half_open->stime = time(NULL);
    tcp_half_open->action = action; 

    GetTcpHalfOpenKeyHash(tcp_half_open, tcp_half_open->key_hash, TCP_HALF_OPEN_KEY_MAX_LEN);

    DEBUG_TRACE("SpAM: Init tcp half open entry from pkt: %s",
                TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)));
}

static char* TcpHalfOpenEntryToString(TcpHalfOpen* tcp_half_open, char* buff, size_t buff_len) {
    if ( ( !tcp_half_open ) || ( !buff ) || ( buff_len == 0 ) ) {
        return buff;
    }

    snprintf(buff, buff_len,
             "key_hash [server<->client] : %s, "
             "count: %u, "
             "time:  %ld",
             tcp_half_open->key_hash,
             tcp_half_open->count,
             tcp_half_open->stime);

    return buff;
}

static void EnqueueTcpHalfOpenEntry(TcpSession* sess, int action) {
    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif

    TcpHalfOpen* tcp_half_open = NULL;

    if ( !sess ) {
        return;
    }

    tcp_half_open = (TcpHalfOpen*) calloc(1, sizeof(TcpHalfOpen));

    if ( !tcp_half_open ) {
        return;
    }

    InitTcpHalfOpenEntry(sess, action, tcp_half_open);

    DEBUG_TRACE("SpAM: Enqueue tcp half open entry: %s",
                TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)));

    g_async_queue_push(g_tcp_half_open_qu, tcp_half_open);
    g_tcp_half_open_qu_size++;
}

void AddTcpHalfOpenEntry(TcpHalfOpen* tcp_half_open) {
    pthread_mutex_lock(&g_tcp_half_open_ht_lock);
    _AddTcpHalfOpenEntry(tcp_half_open); 
    pthread_mutex_unlock(&g_tcp_half_open_ht_lock);
}

void DeleteTcpHalfOpenEntry(TcpHalfOpen* tcp_half_open) {
    pthread_mutex_lock(&g_tcp_half_open_ht_lock);
    _DeleteTcpHalfOpenEntry(tcp_half_open); 
    pthread_mutex_unlock(&g_tcp_half_open_ht_lock);
}

gboolean ProcessEmbryonicConnection(gpointer key, gpointer value, gpointer data) { 
    //static uint64_t yield_counter = 0;
    struct timeval* tv = (struct timeval*) data;
    char* key_str = (char*) key; 
    TcpHalfOpen* tcp_half_open = (TcpHalfOpen*) value;
    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif

    if ( ( !tv ) || ( !key_str ) || ( !tcp_half_open ) ) {
        return FALSE;
    }

    /* yield_counter++;
    if ( ( yield_counter % 10 ) == 0 ) {
       pthread_yield();
    } */

    DEBUG_TRACE("SpAM: Checking if its tcp half open conneciton: %s, current time: %ld",
                TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)),
                tv->tv_sec);

    if ( ( tv->tv_sec - tcp_half_open->stime ) >=  PTHO_THRESHOLD_TIME ) {
        DEBUG_TRACE("SpAM: Detected tcp half open conneciton: %s",
                    TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)));

        if ( g_monitor_sp_activity_conf.process_tcp_half_open_cb ) {
            g_num_of_embryonic_conn_detected++;
            g_monitor_sp_activity_conf.process_tcp_half_open_cb(tcp_half_open);
        }

        g_tcp_half_open_ht_size--;
        return TRUE;
    }

    return FALSE;
}

static void* ProcessTcpHalfOpenQueueThread(void* data)
{
    TcpHalfOpen* tcp_half_open = NULL;

    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif

    while ( !g_end_is_nigh ) {
        //TBD - Check if pthread_cond_wait and pthread_cond_signal would be
        //      better approach than sleep+timeout
        //tcp_half_open = g_async_queue_timeout_pop(g_tcp_half_open_qu, 120000000);
        tcp_half_open = g_async_queue_pop(g_tcp_half_open_qu);

        if ( !tcp_half_open ) { continue; }

        if ( g_tcp_half_open_qu_size != 0 ) { g_tcp_half_open_qu_size--; }

        DEBUG_TRACE("SpAM: Dequeued tcp half open entry: %s",
                    TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)));

        switch(tcp_half_open->action) {
            case SA_ACTION_ENTRY_ADD:
                 AddTcpHalfOpenEntry(tcp_half_open);
                 break;

            case SA_ACTION_ENTRY_DELETE:
                 DeleteTcpHalfOpenEntry(tcp_half_open);
                 break;

            case SA_ACTION_NONE:
            default:
                 free(tcp_half_open);
                 break;
        }
    }

    return NULL;
}

static void* ProcessTcpHalfOpenEntriesThread(void* data) {
    struct timeval tv;
    struct timespec ts;
    int ret = 0;

    memset(&tv, 0, sizeof(struct timeval));
    memset(&ts, 0, sizeof(struct timespec));

    while ( !g_end_is_nigh ) {
        pthread_mutex_lock(&g_tcp_half_open_ht_lock);

        gettimeofday(&tv, NULL);
        ts.tv_sec = tv.tv_sec + PTHO_WAIT_TIME_SEC;
        ts.tv_nsec = tv.tv_usec * 1000;

        ret = pthread_cond_timedwait(&g_tcp_half_open_cond,
                                     &g_tcp_half_open_ht_lock,
                                     &ts);

        if ( ret == ETIMEDOUT ) {
            DEBUG_TRACE("SpAM: Processing all tcp half open entries");

            gettimeofday(&tv, NULL);
            g_hash_table_foreach_remove(g_tcp_half_open_ht,
                                        ProcessEmbryonicConnection,
                                        &tv);
        }

        pthread_mutex_unlock(&g_tcp_half_open_ht_lock);
    }

    return NULL;
}

static int InitSpuriousActivityMonitor(MonitorSpActivityConf* monitor_sp_activity_conf) {
    DEBUG_TRACE("SpAM: Initializing spurious activity monitoring");

    if ( !monitor_sp_activity_conf ) { 
        return SA_ERROR;
    }

    memcpy(&g_monitor_sp_activity_conf, monitor_sp_activity_conf,
           sizeof(MonitorSpActivityConf));
    
    g_tcp_half_open_ht = g_hash_table_new_full(g_str_hash,
                                               g_str_equal,
                                               free,
                                               free);

    g_tcp_half_open_qu = g_async_queue_new_full(_FreeTcpHalfOpenEntry);

    if ( pthread_mutex_init(&g_tcp_half_open_ht_lock, NULL ) != 0 ) {
        return SA_ERROR;
    }

    if ( pthread_cond_init(&g_tcp_half_open_cond, NULL ) != 0 ) {
        return SA_ERROR;
    }

    if ( pthread_create(&g_tcp_half_open_ht_tid,
                        NULL,
                        ProcessTcpHalfOpenEntriesThread,
                        NULL) != 0 ) {
        return SA_ERROR;
    }

    if ( pthread_create(&g_tcp_half_open_qu_tid,
                        NULL,
                        ProcessTcpHalfOpenQueueThread,
                        NULL) != 0 ) {
        return SA_ERROR;
    }

    g_sp_activity_monitor_initialized = 1;
    DEBUG_TRACE("SpAM: Initializing spurious activity monitoring : Done");
    return SA_OK;
}

static void DeinitSpuriousActivityMonitor(void) {
    DEBUG_TRACE("SpAM: DeInitializing spurious activity monitoring");

    pthread_cond_destroy(&g_tcp_half_open_cond); 
    pthread_mutex_destroy(&g_tcp_half_open_ht_lock); 

    if ( g_tcp_half_open_ht ) {
         g_hash_table_destroy(g_tcp_half_open_ht);
    } 

    if ( g_tcp_half_open_qu ) {
         g_async_queue_unref(g_tcp_half_open_qu);
    }
}

int StartMonitoringSpuriousActivity(MonitorSpActivityConf* monitor_sp_activity_conf) {
    int ret = SA_ERROR;

    if ( !monitor_sp_activity_conf ) {
        return SA_ERROR;
    }

    DEBUG_TRACE("SpAM: Start monitoring spurious activity");

    ret = InitSpuriousActivityMonitor(monitor_sp_activity_conf);
    if ( ret != SA_OK ) {
        return SA_ERROR;
    }

    return ret;
}

int StopMonitoringSpuriousActivity(void) {
    TcpHalfOpen* tcp_half_open = NULL;
    DEBUG_TRACE("SpAM: Stop monitoring spurious activity");

    g_end_is_nigh = 1;    

    //hack: enqueue nop data
    tcp_half_open = (TcpHalfOpen*) calloc(1, sizeof(TcpHalfOpen));
    tcp_half_open->action = SA_ACTION_NONE;
    g_async_queue_push(g_tcp_half_open_qu, tcp_half_open);

    pthread_join(g_tcp_half_open_ht_tid, NULL);
    pthread_join(g_tcp_half_open_qu_tid, NULL);

    DeinitSpuriousActivityMonitor();
    return SA_OK;
}

void AnalyzeSpActivity(TcpSession* sess, void* data, int data_type) {
    uint32_t flags = 0;
    int action = SA_ACTION_NONE;
    gboolean enque = FALSE;

    if ( !g_sp_activity_monitor_initialized ) {
        return;
    }

    if ( data_type == SA_DATA_TYPE_TCP_FLAGS ) {
        flags = *((uint8_t *)data);

        if( ( flags & 0xFF ) == TH_SYN ) {
            action = SA_ACTION_ENTRY_ADD;
            enque = TRUE;
        } else if( ( flags & TH_SYN ) && ( flags & TH_ACK ) ) {
            action = SA_ACTION_ENTRY_DELETE;
            enque = TRUE;
        }

        if ( enque == TRUE ) {
            EnqueueTcpHalfOpenEntry(sess, action);
        }
    }
}

void AnalyzeSpActivityV2(struct ip* ip_header, struct tcphdr* tcp_header) {
    #ifdef NM_ENABLE_TRACE
    char buff[256] = {0,};
    #endif
    uint32_t flags = 0;
    int action = SA_ACTION_NONE;
    gboolean enque = FALSE;
    TcpHalfOpen* tcp_half_open = NULL;

    if ( !g_sp_activity_monitor_initialized ||
         !ip_header || !tcp_header ) {
        return;
    }

    flags = tcp_header->th_flags;

    if( ( flags & 0xFF ) == TH_SYN ) {
        action = SA_ACTION_ENTRY_ADD;
    } else if( ( flags & TH_SYN ) && ( flags & TH_ACK ) ) {
        action = SA_ACTION_ENTRY_DELETE;
    } else {
        return;
    }

    tcp_half_open = (TcpHalfOpen*) calloc(1, sizeof(TcpHalfOpen));

    if ( !tcp_half_open ) {
        return;
    }

    if ( ( flags & 0xFF ) == TH_SYN ) { // from client
        tcp_half_open->server_ip = INADDR_IP( ip_header->ip_dst );
        tcp_half_open->client_ip = INADDR_IP( ip_header->ip_src );
        tcp_half_open->server_port = ntohs(tcp_header->th_dport);
        tcp_half_open->client_port = ntohs(tcp_header->th_sport);
    } else { //from server
        tcp_half_open->server_ip = INADDR_IP( ip_header->ip_src );
        tcp_half_open->client_ip = INADDR_IP( ip_header->ip_dst );
        tcp_half_open->server_port = ntohs(tcp_header->th_sport);
        tcp_half_open->client_port = ntohs(tcp_header->th_dport);
    }

    tcp_half_open->count = 1;
    tcp_half_open->stime = time(NULL);
    tcp_half_open->action = action;

    GetTcpHalfOpenKeyHash(tcp_half_open, tcp_half_open->key_hash, TCP_HALF_OPEN_KEY_MAX_LEN);

    DEBUG_TRACE("SpAM: AnalyzeSpActivityV2 - Init tcp half open entry from pkt: %s",
                TcpHalfOpenEntryToString(tcp_half_open, buff, sizeof(buff)));

    g_async_queue_push(g_tcp_half_open_qu, tcp_half_open);
    g_tcp_half_open_qu_size++;
}

uint32_t GetEmbryonicConnectionQueueSize(void) {
    return g_tcp_half_open_qu_size;
}

uint32_t GetEmbryonicConnectionHashTableSize(void) {
    return g_tcp_half_open_ht_size;
}

uint32_t GetNumberOfEmbryonicConnectionDetected(void) {
    return g_num_of_embryonic_conn_detected;
}
