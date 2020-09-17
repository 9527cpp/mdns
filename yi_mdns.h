#ifndef __YI_MDNS__
#define __YI_MDNS__

#ifdef __cplusplus
extern "C"{
#endif

typedef void (*dns_callback)(char * bind_key);
void *YI_ETH_MDNS_INIT(const char * ip,const char * pseude_did,const char * did,int  HD_VER,dns_callback cb,char * bind_key,char *interface);
void YI_ETH_MDNS_RUN();
void YI_ETH_MDNS_REINIT();

#ifdef __cpulsplus
}
#endif

#endif
