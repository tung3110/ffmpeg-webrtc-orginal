//
// Copyright (c) 2019-2022 yanggaofeng
//
#include <yangutil/sys/YangSocket.h>
#include <yangutil/sys/YangLog.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#pragma comment(lib,"Iphlpapi")

#else
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#endif

yangbool yang_socket_filterIp(char* ip){
    if(yang_memcmp(ip,"127.0.0",7)==0 || yang_memcmp(ip,"169.",4)==0 || yang_memcmp(ip,"192.168.56.",11)==0)
        return yangfalse;

    return yangtrue;
}


int32_t yang_getIp( YangIpFamilyType familyType,char* domain, char* ip)
{

    struct addrinfo *addinfo=NULL,*addr=NULL;

    if(getaddrinfo(domain, NULL, NULL, &addinfo)!=0) {
        yang_strcpy(ip,domain);
        goto cleanup;
    }

    for (addr = addinfo; addr != NULL; addr = addr->ai_next) {
        if (addr->ai_family == AF_INET) {
            if(familyType==Yang_IpFamilyType_IPV4)
                inet_ntop(AF_INET, &((struct sockaddr_in*) addr->ai_addr)->sin_addr, ip, INET_ADDRSTRLEN);

            goto cleanup;
        } else if (addr->ai_family == AF_INET6) {

            if(familyType==Yang_IpFamilyType_IPV6)
                inet_ntop(AF_INET6, &((struct sockaddr_in6*) addr->ai_addr)->sin6_addr, ip, INET6_ADDRSTRLEN);

           goto cleanup;
        }
    }
    cleanup:
    if(addinfo) freeaddrinfo(addinfo);
    return Yang_Ok;
}


int32_t yang_getLocalInfoList(YangIpFamilyType familyType,YangStringVector* vecs)
{

    char ip[128];
#ifdef _WIN32
    DWORD ret, outBufLen;
    IP_ADAPTER_ADDRESSES *adapterAddresses=NULL, *adress  = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS uaddress = NULL;
    ret=GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &outBufLen);
    adapterAddresses=(IP_ADAPTER_ADDRESSES*) yang_calloc(outBufLen,1);
    ret= GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapterAddresses, &outBufLen);

    for (adress = adapterAddresses; adress != NULL ; adress = adress->Next) {

        for (uaddress = adress->FirstUnicastAddress; uaddress != NULL; uaddress = uaddress->Next) {

            yang_memset(ip,0,sizeof(ip));
            if (uaddress->Address.lpSockaddr->sa_family == AF_INET) {
                if(familyType==Yang_IpFamilyType_IPV4){
                    inet_ntop(AF_INET, &((struct sockaddr_in*) (uaddress->Address.lpSockaddr))->sin_addr, ip, INET_ADDRSTRLEN);
                    yang_insert_stringVector(vecs,ip);
                }

            } else {
                struct sockaddr_in6* ip6Addr = ((struct sockaddr_in6*) (uaddress->Address.lpSockaddr));
                if (IN6_IS_ADDR_UNSPECIFIED(&ip6Addr->sin6_addr) || IN6_IS_ADDR_LINKLOCAL(&ip6Addr->sin6_addr) ||
                        IN6_IS_ADDR_SITELOCAL(&ip6Addr->sin6_addr)) {
                    continue;
                }
                if(familyType==Yang_IpFamilyType_IPV6){
                    inet_ntop(AF_INET6, &ip6Addr->sin6_addr, ip, INET6_ADDRSTRLEN);
                    yang_insert_stringVector(vecs,ip);

                }

            }
        }
    }

    yang_free(adapterAddresses);

#else
    struct ifaddrs * address=NULL;
    struct ifaddrs * ifAddr=NULL;
    getifaddrs(&address);
    ifAddr=address;
    while (ifAddr!=NULL)
    {
        if((ifAddr->ifa_flags & IFF_LOOPBACK) == 0&&(ifAddr->ifa_flags & IFF_RUNNING) > 0){
            yang_memset(ip,0,sizeof(ip));
            if (ifAddr->ifa_addr->sa_family==AF_INET) { //ipv4
                if(familyType==Yang_IpFamilyType_IPV4){

                    inet_ntop(AF_INET, &((struct sockaddr_in*)ifAddr->ifa_addr)->sin_addr, ip, INET_ADDRSTRLEN);
                    yang_insert_stringVector(vecs,ip);
                }
            } else if (ifAddr->ifa_addr->sa_family==AF_INET6) { // ipv6
                if(familyType==Yang_IpFamilyType_IPV6){

                    inet_ntop(AF_INET6, &((struct sockaddr_in*)ifAddr->ifa_addr)->sin_addr, ip, INET6_ADDRSTRLEN);
                    yang_insert_stringVector(vecs,ip);
                }
            }

        }
        ifAddr=ifAddr->ifa_next;
    }
    if (address != NULL) {
        freeifaddrs(address);
    }
#endif
    return 0;

}

#ifdef _WIN32
int32_t yang_getLocalInfo(YangIpFamilyType familyType,char* ipAddress){
    int32_t err = ERROR_SOCKET;
    char ip[128];
    DWORD ret, outBufLen;
    IP_ADAPTER_ADDRESSES *adapterAddresses=NULL, *adress  = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS uaddress = NULL;
    ret=GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &outBufLen);
    adapterAddresses=(IP_ADAPTER_ADDRESSES*) yang_calloc(outBufLen,1);
    ret= GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapterAddresses, &outBufLen);
    yangbool isLoop=yangtrue;
    for (adress = adapterAddresses; adress != NULL&&isLoop ; adress = adress->Next) {

        for (uaddress = adress->FirstUnicastAddress; uaddress != NULL; uaddress = uaddress->Next) {
            yang_memset(ip,0,sizeof(ip));

            if (uaddress->Address.lpSockaddr->sa_family == AF_INET) {
                if(familyType==Yang_IpFamilyType_IPV4){
                    inet_ntop(AF_INET,  &((struct sockaddr_in*) (uaddress->Address.lpSockaddr))->sin_addr, ip, INET_ADDRSTRLEN);
                    if(yang_socket_filterIp(ip)){
                        yang_strcpy(ipAddress,ip);
                        err=Yang_Ok;
                        isLoop=yangfalse;
                        break;
                    }
                }

            } else {
                struct sockaddr_in6* ip6Addr = ((struct sockaddr_in6*) (uaddress->Address.lpSockaddr));
                if (IN6_IS_ADDR_UNSPECIFIED(&ip6Addr->sin6_addr) || IN6_IS_ADDR_LINKLOCAL(&ip6Addr->sin6_addr) ||
                        IN6_IS_ADDR_SITELOCAL(&ip6Addr->sin6_addr)) {
                    continue;
                }

                if(familyType==Yang_IpFamilyType_IPV6){
                    inet_ntop(AF_INET6, &ip6Addr->sin6_addr, ip, INET6_ADDRSTRLEN);
                    yang_strcpy(ipAddress,ip);
                    err=Yang_Ok;
                    isLoop=yangfalse;
                    break;
                }

            }
        }
    }

    yang_free(adapterAddresses);
    return err;
}



#else

#if 0
int32_t yang_getLocalInfo(YangIpFamilyType familyType,char* ipAddress)
{
    int32_t err=ERROR_SOCKET;
    struct ifaddrs *address=NULL,*ifAddr=NULL;

    getifaddrs(&address);
    char ip[128];
    ifAddr=address;
    while (ifAddr!=NULL)
    {   
        yang_trace("\nifaddr: %s, %d, ", ifAddr->ifa_name, ifAddr->ifa_addr->sa_family);
        if((ifAddr->ifa_flags & IFF_LOOPBACK) == 0&&(ifAddr->ifa_flags & IFF_RUNNING) > 0){
        	yang_memset(ip,0,sizeof(ip));            
            if (ifAddr->ifa_addr->sa_family==AF_INET) { //ipv4
                if(familyType==Yang_IpFamilyType_IPV4){
                    inet_ntop(AF_INET, &((struct sockaddr_in*)ifAddr->ifa_addr)->sin_addr, ip, INET_ADDRSTRLEN);
                    if(yang_socket_filterIp(ip)){
                        if (yang_strncmp(ifAddr->ifa_name, "eth0", 4) == 0) {
                        yang_strcpy(ipAddress,ip);
                        }
                        for(int i=0;i<14;i++)
                            yang_trace("%d ", ip);
                        yang_trace("\n");
                        err=Yang_Ok;
                        break;
                    }
                }


            } else if (ifAddr->ifa_addr->sa_family==AF_INET6) { // ipv6
                if(familyType==Yang_IpFamilyType_IPV6){
                    inet_ntop(AF_INET6, &((struct sockaddr_in*)ifAddr->ifa_addr)->sin_addr, ip, INET6_ADDRSTRLEN);
                    yang_strcpy(ipAddress,ip);
                    for(int i=0;i<14;i++)
                        yang_trace("%d ", ipAddress);
                    yang_trace("\n");
                    err=Yang_Ok;
                    break;
                }

            }

        }
        ifAddr=ifAddr->ifa_next;
    }
    if (address != NULL) {
        freeifaddrs(address);
    }
    return err;

}

#endif // 0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <net/if.h>

int32_t yang_getLocalInfo(YangIpFamilyType familyType,char* ipAddress)
{
    int32_t err=ERROR_SOCKET;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        perror("socket");
        return;
    }

    // Đặt timeout để tránh treo
    struct timeval tv = {2, 0};  // 2 giây timeout
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct {
        struct nlmsghdr nh;
        struct ifaddrmsg ifa;
    } req;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nh.nlmsg_type = RTM_GETADDR;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;
    req.ifa.ifa_family = AF_UNSPEC;  // Lấy cả IPv4 & IPv6

    if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
        perror("send");
        close(fd);
        return;
    }

    char buffer[8192];
    int len;

    while ((len = recv(fd, buffer, sizeof(buffer), 0)) > 0) {
        struct nlmsghdr *nh;
        for (nh = (struct nlmsghdr *)buffer; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                printf("Received NLMSG_DONE, stopping.\n");
                close(fd);
                return;  // Thoát khi nhận đủ dữ liệu
            }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Netlink error received.\n");
                close(fd);
                return;
            }

            struct ifaddrmsg *ifa = NLMSG_DATA(nh);
            struct rtattr *rta = IFA_RTA(ifa);
            int rta_len = IFA_PAYLOAD(nh);

            char ifname[IF_NAMESIZE];
            if_indextoname(ifa->ifa_index, ifname);

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                if (rta->rta_type == IFA_ADDRESS) {
                    char ip[INET6_ADDRSTRLEN] = {0};
                    if (ifa->ifa_family == AF_INET) {
                        inet_ntop(AF_INET, RTA_DATA(rta), ip, sizeof(ip));
                        printf("Interface: %s, IPv4: %s\n", ifname, ip);
                        if(familyType==Yang_IpFamilyType_IPV4){
                            if(yang_socket_filterIp(ip)){
                                yang_strcpy(ipAddress,ip);
                                err=Yang_Ok;
                                break;
                            }
                        }
                    } else if (ifa->ifa_family == AF_INET6) {
                        inet_ntop(AF_INET6, RTA_DATA(rta), ip, sizeof(ip));
                        printf("Interface: %s, IPv6: %s\n", ifname, ip);
                        if(familyType==Yang_IpFamilyType_IPV6){
                            yang_strcpy(ipAddress,ip);
                            err=Yang_Ok;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (len < 0) {
        perror("recv timeout or error");
    }

    close(fd);
    return err;
}

#endif
