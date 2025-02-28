#ifndef __SPURIOUS_ACTIVITY__
#define __SPURIOUS_ACTIVITY__

#ifdef __cplusplus
extern "C" {
#endif

#define SA_OK     0
#define SA_ERROR  1

#define PTHO_WAIT_TIME_SEC 20
#define PTHO_THRESHOLD_TIME 10  //3sec 

#define TCP_HALF_OPEN_KEY_MAX_LEN 60


enum {
    SA_DATA_TYPE_TCP_FLAGS  = 1
};

enum {
    SA_ACTION_NONE = 0,
    SA_ACTION_ENTRY_ADD, 
    SA_ACTION_ENTRY_DELETE
};

typedef struct  __attribute__((__packed__)) _TcpHalfOpen {
    char key_hash[TCP_HALF_OPEN_KEY_MAX_LEN];
    uint32_t client_ip;
    uint32_t server_ip;
    u_int16_t client_port;
    u_int16_t server_port;
    u_int16_t count;
    time_t stime;
    u_int8_t action;
} TcpHalfOpen;

typedef void (*PROCESS_TCP_HALF_OPEN_CB)(TcpHalfOpen* tcp_half_open);

typedef struct _MonitorSpActivityConf {
    PROCESS_TCP_HALF_OPEN_CB process_tcp_half_open_cb;
} MonitorSpActivityConf;

int StartMonitoringSpuriousActivity(MonitorSpActivityConf* MonitorSpActivityConf);
int StopMonitoringSpuriousActivity(void);

uint32_t GetEmbryonicConnectionQueueSize(void);
uint32_t GetEmbryonicConnectionHashTableSize(void);
uint32_t GetNumberOfEmbryonicConnectionDetected(void);

#ifdef __cplusplus
}
#endif

#endif //__SPURIOUS_ACTIVITY__
