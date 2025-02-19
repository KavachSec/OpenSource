#ifndef __SPURIOUS_ACTIVITY_EX__
#define __SPURIOUS_ACTIVITY_EX__

#include "dssl_defs.h"
#include "spurious_activity.h" 

#ifdef __cplusplus
extern "C" {
#endif

void AnalyzeSpActivity(TcpSession* sess, void* data, int data_type);
void AnalyzeSpActivityV2(struct ip* ip_header, struct tcphdr* tcp_header);

#ifdef __cplusplus
}
#endif

#endif //__SPURIOUS_ACTIVITY_EX__
