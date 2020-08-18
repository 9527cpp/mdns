/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>          // For printf()
#include <stdlib.h>         // For exit() etc.
#include <string.h>         // For strlen() etc.
#include <unistd.h>         // For select()
#include <errno.h>          // For errno, EINTR
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include "mDNSEmbeddedAPI.h" // Defines the interface to the client layer above
#include "mDNSPosix.h"      // Defines the specific types needed to run mDNS on this platform
#include "mDNSUNP.h"        // For daemon()

#define MDNS_PORT_NUMBER 577
#define MDNS_OPEN_TIMEOUT (10*60*10) //10 min
#define MDNS_OPEN_TIMEOUT_WHEN_BINDED (3*60*10) //3 min
#define MDNS_DEV_BIND_TIMEOUT 90 //90 s

#define MULTICAST_MAXBUF 256
#define MULTICAST_PUERTO 22400
#define MULTICAST_GRUPO "224.0.0.224"
#define MULTICAST_YIFLAG "XIAOYI"
#define HD_VER_N10 22
/* #define IP_ADD_MEMBERSHIP 12 */
#ifndef MIN
    #define MIN(x,y) ((x)<(y)?(x):(y))
#endif



typedef enum
{
    BIND_FAIL = 0,             // 设备请求绑定，后台返回绑定失败
    BIND_SUCCESS = 1,
    BIND_AUTH_FAILED = 2,      // 从app收到的DID的第8到第14这7个字节，和设备的DID不匹配
    BIND_RECV_DATA_ERROR = 3,  // 设备从socket里面读数据失败
    BIND_DEVICE_TIMEOUT = 4,   // 设备自身运行超时(100s)，提示用户重新绑定    
    BIND_NETWORK_TIMEOUT = 5,  // 设备请求后台超时， 提示用户设备网络不好
}bind_result_e;

typedef enum 
{ 
     BIND_STATE_IDLE = 0x0, 
     BIND_STATE_START, 
     BIND_STATE_NO_E, 
     BIND_STATE_YES_E, 
     BIND_STATE_TIMEOUT, 
     BIND_STATE_CHECK_DID, 
     BIND_STATE_BIND_KEY, 
     BIND_STATE_FAIL, 
}bind_state_e;

unsigned int mdns_open_timeout;
int mdns_bind_state;
static mDNS mDNSStorage;       // mDNS core uses this to store its globals
static mDNS_PlatformSupport PlatformStorage;  // Stores this platform's globals

mDNSexport const char ProgramName[] = "mdnsResponder";
const char *serviceDomain = "local.";
int portNumber = MDNS_PORT_NUMBER;

typedef struct PosixService PosixService;

struct PosixService {
    ServiceRecordSet coreServ;
    struct PosixService *next;
    int serviceID;
};

PosixService *gServiceList;
int gServiceID;

struct MdnsContext{
    mDNSBool gMdnsRunning;
    char pseude_did[64];
    char did[64];
    char ip[32];
};

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char * base64_encode( const unsigned char * bindata, char * base64, int binlength )
{
    int i, j;
    unsigned char current;
    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return base64;
}

int base64_decode(const char * base64, unsigned char * bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}

static int xor_encrypt(char* source, int out_len, char* out)
{
    int i = 0;
    int source_length = strlen(source);
	char* pass = "89JFSjo8HUbhou5776NJOMp9i90ghg7Y78G78t68899y79HY7g7y87y9ED45Ew30O0jkkl";
    int pass_length = strlen(pass);
    memset(out,0,out_len);
    for(i = 0; i < source_length; i++)
    {
        out[i] = source[i]^pass[i%pass_length];
        if(out[i] == 0)
        {
            out[i] = source[i];
        }
    }
    return 0;
}

static void RegistrationCallback(mDNS *const m, ServiceRecordSet *const thisRegistration, mStatus status)
{
    switch (status) {
    case mStatus_NoError:
        debugf("Callback: %##s Name Registered",   thisRegistration->RR_SRV.resrec.name->c);
        break;
    case mStatus_NameConflict:
        debugf("Callback: %##s Name Conflict",     thisRegistration->RR_SRV.resrec.name->c);
        status = mDNS_RenameAndReregisterService(m, thisRegistration, mDNSNULL);
        assert(status == mStatus_NoError);
        break;
    case mStatus_MemFree:
        debugf("Callback: %##s Memory Free",       thisRegistration->RR_SRV.resrec.name->c);
   #if !defined(NDEBUG)
        {
            PosixService *cursor;
            cursor = gServiceList;
            while (cursor != NULL) {
                assert(&cursor->coreServ != thisRegistration);
                cursor = cursor->next;
            }
        }
   #endif
        free(thisRegistration);
        break;
    default:
        debugf("Callback: %##s Unknown Status %ld", thisRegistration->RR_SRV.resrec.name->c, status);
        break;
    }
}


static mStatus RegisterOneService(const char *  richTextName,
                                  const char *  serviceType,
                                  const char *  serviceDomain,
                                  const mDNSu8 text[],
                                  mDNSu16 textLen,
                                  long portNumber)
{
    mStatus status;
    PosixService *      thisServ;
    domainlabel name;
    domainname type;
    domainname domain;
    status = mStatus_NoError;
    thisServ = (PosixService *) malloc(sizeof(*thisServ));
    if (thisServ == NULL) {
        status = mStatus_NoMemoryErr;
    }
    if (status == mStatus_NoError) {
        MakeDomainLabelFromLiteralString(&name,  richTextName);
        MakeDomainNameFromDNSNameString(&type, serviceType);
        MakeDomainNameFromDNSNameString(&domain, serviceDomain);
        status = mDNS_RegisterService(&mDNSStorage, &thisServ->coreServ,
                                      &name, &type, &domain, // Name, type, domain
                                      NULL, mDNSOpaque16fromIntVal(portNumber),
                                      text, textLen, // TXT data, length
                                      NULL, 0,      // Subtypes
                                      mDNSInterface_Any, // Interface ID
                                      RegistrationCallback, thisServ, 0); // Callback, context, flags
    }
    if (status == mStatus_NoError) {
        thisServ->serviceID = gServiceID;
        gServiceID += 1;
        thisServ->next = gServiceList;
        gServiceList = thisServ;
        if (gMDNSPlatformPosixVerboseLevel > 0) {
            printf("Registered service %d, name \"%s\", type \"%s\", domain \"%s\",  port %ld", 
                thisServ->serviceID, richTextName, serviceType, serviceDomain, portNumber);
        }
    } else {
        if (thisServ != NULL) {
            free(thisServ);
        }
    }
    return status;
}

static void DeregisterOurServices(void)
{
    PosixService *thisServ;
    int thisServID;
    while (gServiceList != NULL) {
        thisServ = gServiceList;
        gServiceList = thisServ->next;
        thisServID = thisServ->serviceID;
        mDNS_DeregisterService(&mDNSStorage, &thisServ->coreServ);
        if (gMDNSPlatformPosixVerboseLevel > 0) 
        {
            printf( "Deregistered service %d\r\n", thisServ->serviceID);
        }
    }
}

void * run_recv_data(void * arg)
{
    int socket_fd = -1,  connect_fd = -1;
    struct sockaddr_in servaddr;
    char buff[32] = {0};
    int recv_len = 0;
    struct timeval recv_timeout = {0, 0};
    int bind_result = BIND_FAIL;
    int on = 1;
    struct ifreq ifr={};
    struct MdnsContext * context = (struct MdnsContext *)arg;
    pthread_detach(pthread_self());
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0)goto EXIT_STAT_1;
    if((setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)goto EXIT_STAT_1;
    strcpy(ifr.ifr_name,"eth0");
    if( setsockopt(socket_fd,SOL_SOCKET,SO_BINDTODEVICE,(char *)&ifr,sizeof(ifr))<0 ) goto EXIT_STAT_1;
    memset(&servaddr, 0x00, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MDNS_PORT_NUMBER);
    servaddr.sin_addr.s_addr = 0;
    printf("socket bind ip:%s, port:%d\r\n", context->ip, ntohs(servaddr.sin_port));
    if(bind(socket_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)goto EXIT_STAT_1;
    if(listen(socket_fd, 10) < 0)goto EXIT_STAT_1;

	while(context->gMdnsRunning)
	{
        connect_fd = accept(socket_fd, NULL, NULL);
        if(connect_fd < 0)goto CONTINUE_STAT_1;
        recv_timeout.tv_sec = 5;
        setsockopt(connect_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)(&recv_timeout), sizeof(struct timeval));
        recv_len = recv(connect_fd, buff, sizeof(buff), 0);
        printf("recv from socket:%s, len=%d\r\n", buff, recv_len);
        if(recv_len > 0)
        {
            if(0 == strncmp(buff, context->did+7, 7))
            {
                char bindkey[32] = {0};
                strncpy(bindkey, buff+7, sizeof(bindkey)-7);
            }
            else
            {
                bind_result = BIND_AUTH_FAILED;
                send(connect_fd, (char *)&bind_result, sizeof(bind_result), 0);
                goto CONTINUE_STAT_1;
            }
        }
        else
        {
            bind_result = BIND_RECV_DATA_ERROR;
            send(connect_fd, (char *)&bind_result, sizeof(bind_result), 0);
            goto CONTINUE_STAT_1;
        }
        int self_timeout = 0;
        while(self_timeout < MDNS_DEV_BIND_TIMEOUT*10)
        {
            if(mdns_bind_state != BIND_STATE_IDLE)break;
            self_timeout++;
            usleep(1000*100);
        }
        if(MDNS_DEV_BIND_TIMEOUT*10 == self_timeout)
        {
            bind_result = BIND_DEVICE_TIMEOUT;
            send(connect_fd, (char *)&bind_result, sizeof(bind_result), 0);
            goto CONTINUE_STAT_1;
        }
        printf( "bind state = %d\r\n", mdns_bind_state);
        if(BIND_STATE_YES_E == mdns_bind_state)
        {
            printf( "bind success, exit!");
            bind_result = BIND_SUCCESS;
            send(connect_fd, (char *)&bind_result, sizeof(bind_result), 0);
            sleep(1);
            goto EXIT_STAT_1;
        }
        else if(BIND_STATE_TIMEOUT == mdns_bind_state)//network timeout
        {
            printf( "network timeout!");
            bind_result = BIND_NETWORK_TIMEOUT;
            send(connect_fd, (char *)&bind_result, sizeof(bind_result), 0);
            mdns_bind_state = BIND_STATE_IDLE;
            goto CONTINUE_STAT_1;
        }
        else if(BIND_STATE_FAIL == mdns_bind_state)
        {
            printf( "bind fail!");
            bind_result = BIND_FAIL;
            send(connect_fd, (char *)&bind_result, sizeof(bind_result), 0);
            mdns_bind_state = BIND_STATE_IDLE;
            goto CONTINUE_STAT_1;
        }
CONTINUE_STAT_1:
        close(connect_fd);
        connect_fd = -1;
        continue;
    }
EXIT_STAT_1:
    close(socket_fd);
    socket_fd = -1;
    return NULL;
}

void * run_accept_multicast(void * arg)
{
    int ret = 1;
    int fd, n, r;
    int client_sock = -1;
    struct sockaddr_in srv, cli, dst;
    struct ip_mreq mreq;
    char buf[MULTICAST_MAXBUF] = {0};
    char decode_str[MULTICAST_MAXBUF] = {0};
    int decode_len = 0;
    char ip[32] = {0};
    int port = 0;
    char did_xor[64] = {0};
    char send_buf[64] = {0};
    int flag_len = strlen(MULTICAST_YIFLAG);
    struct MdnsContext * context = (struct MdnsContext *)arg;

    pthread_detach(pthread_self());
    memset( &srv, 0, sizeof(struct sockaddr_in) );
    memset( &cli, 0, sizeof(struct sockaddr_in) );
    memset( &dst, 0, sizeof(struct sockaddr_in) );
    memset( &mreq, 0, sizeof(struct ip_mreq) );
    
    srv.sin_family = AF_INET;
    srv.sin_port = htons(MULTICAST_PUERTO);
    printf("ip:%s\r\n",context->ip);
    if( inet_aton(MULTICAST_GRUPO, &srv.sin_addr ) < 0 ){printf("1\r\n");goto EXIT_STAT_1;}
    if( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){printf("2\r\n");goto EXIT_STAT_1;}
    if( bind(fd, (struct sockaddr *)&srv, sizeof(srv)) < 0 ){printf("3\r\n");goto EXIT_STAT_1;}
    if (inet_aton(MULTICAST_GRUPO, &mreq.imr_multiaddr) < 0) {printf("4\r\n");goto EXIT_STAT_1;}
    if (inet_aton(context->ip, &(mreq.imr_interface)) < 0){printf("5\r\n");goto EXIT_STAT_1;}
    if(setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP, &mreq,sizeof(mreq)) < 0 ){printf("6\r\n");goto EXIT_STAT_1;}
    n = sizeof(cli);
    printf("start recv multicast data, port:%d group: %s flag: %s\r\n", MULTICAST_PUERTO,MULTICAST_GRUPO, MULTICAST_YIFLAG);

    while(context->gMdnsRunning)
    {
        /// 1: recv
        memset(buf, 0, MULTICAST_MAXBUF);
        if( (r = recvfrom(fd, buf, MULTICAST_MAXBUF, 0, (struct sockaddr *)&cli, (socklen_t*)&n)) < 0 )goto CONTINUE_STAT_2;;
        printf( "from %s: %s\r\n", inet_ntoa(cli.sin_addr), buf);
        if(0 != strncmp(buf, MULTICAST_YIFLAG, flag_len))goto CONTINUE_STAT_2;
        memset(decode_str, 0, MULTICAST_MAXBUF);
        decode_len = base64_decode(buf+flag_len, decode_str);
        if(decode_len <= 0)goto CONTINUE_STAT_2;;
        char *p = strstr(decode_str, ";");
        if(!p)goto CONTINUE_STAT_2;;
        strncpy(ip, decode_str, MIN(sizeof(ip), p-decode_str));
        port = atoi(p+1);
        printf( "ip:%s, port:%d\r\n", ip, port);
        if(port <= 0)goto CONTINUE_STAT_2;;

        /// 2: connect & send rsp
        if((client_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)goto CONTINUE_STAT_1;
        dst.sin_family = AF_INET;
        dst.sin_port = htons(port);
        if( inet_aton(ip, &dst.sin_addr) < 0 )goto CONTINUE_STAT_1; 
        if(connect(client_sock, (struct sockaddr *)&dst, sizeof(struct sockaddr)) < 0)goto CONTINUE_STAT_1;
        if(strlen(context->pseude_did) > 0)memcpy(send_buf, context->pseude_did+2, 2);
        else memcpy(send_buf, "00", 2);
        xor_encrypt(context->did, sizeof(did_xor), did_xor);
        base64_encode(did_xor, send_buf+2, strlen(context->did));
        int send_len = strlen(send_buf);
        send_buf[send_len+1] = '\0';
        send_buf[send_len] = '\n';
        send_len += 2;
        printf( "send %s\r\n", send_buf);
        if(send(client_sock, send_buf, send_len, 0) < 0)goto CONTINUE_STAT_1;
        ret = 0;
        break;
CONTINUE_STAT_1:
            printf("continue_stat_1\r\n");
            close(client_sock);
            client_sock = -1;
CONTINUE_STAT_2:
            printf("continue_stat_2\r\n");
            continue;
    }
EXIT_STAT_2:
    printf("exit_stat_2\r\n");
    close(client_sock);
    client_sock = -1;
EXIT_STAT_1:
    printf("exit_stat_1\r\n");
    close(fd);    
    fd = -1;
    /* return ret; */
    return NULL;
}

void *YI_ETH_MDNS_INIT(const char * ip,const char * pseude_did,const char * did,int HD_VER)
{

    struct MdnsContext * context = NULL;
    mStatus status = mStatus_NoError;
    char serviceName_xor[64] = {0};
    char serviceName[64] = {0};
    char serviceType[64] = {0};
    context = (struct MdnsContext *)malloc(sizeof(struct MdnsContext));
    if(!context)goto EXIT;
    memset(context,0,sizeof(struct MdnsContext));

    if(strlen(pseude_did) > 0)memcpy(serviceName, pseude_did+2, 2);
    else memcpy(serviceName, "00", 2);
    xor_encrypt(did, sizeof(serviceName_xor), serviceName_xor);
    base64_encode(serviceName_xor, serviceName+2, strlen(did));
    snprintf(serviceType, sizeof(serviceType)-1, "_yigateway%03d._tcp.", HD_VER);
    status = mDNS_Init(&mDNSStorage, &PlatformStorage, mDNS_Init_NoCache, mDNS_Init_ZeroCacheSize, 
                        mDNS_Init_AdvertiseLocalAddresses, mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);

    printf("did:%s,pseudo_did:%s\r\n",did,pseude_did);
    printf("RegisterOneService name=%s, type=%s, domain=%s, port=%d\r\n", serviceName, serviceType, serviceDomain,portNumber);
    if (status != mStatus_NoError) 
    {
        printf("mDNS_Init error, status = %d\r\n", status);
        goto EXIT;
    }
    status = RegisterOneService(serviceName, serviceType, serviceDomain, NULL, 0, portNumber);
    if (status != mStatus_NoError)
    {
        mDNS_Close(&mDNSStorage);
        printf("RegisterOneService error, status = %d\r\n", status);
        goto EXIT;
    }

    context->gMdnsRunning = 1;
    memcpy(context->pseude_did,pseude_did,strlen(pseude_did));
    memcpy(context->did,did,strlen(did));
    memcpy(context->ip,ip,strlen(ip));
EXIT:
    return context;
}

void YI_ETH_MDNS_RUN(void * arg){
#if 0
    int ret = 0;
    ret = run_accept_multicast(arg);
    if(!ret){
        run_recv_data(arg);
    }
#else
    pthread_t multicast_t;
    pthread_t recv_t;
    pthread_create(&recv_t,NULL,run_recv_data,arg);
    pthread_create(&multicast_t,NULL,run_accept_multicast,arg);
    while(1){
        sleep(1);
    }
#endif
}

void YI_ETH_MDNS_REINIT(void * arg){
    struct MdnsContext * context = (struct MdnsContext *)arg;
    context->gMdnsRunning = 0;
}

#ifdef BUILD_EXE
int main(int argc,char * argv[]){
    const char * did = "A0136003WJSXBL200310";
    const char * preude_did = "00CN0000000000000000";
    const char * ip = argv[1];
    int HD_VER =22;
    void * context = NULL;
    context = YI_ETH_MDNS_INIT(ip,preude_did,did,HD_VER_N10);   
    YI_ETH_MDNS_RUN(context);

}
#endif
