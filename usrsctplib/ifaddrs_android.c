/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ifaddrs-android-ext.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>

// Returns a pointer to the first byte in the address data (which is
// stored in network byte order).
uint8_t* sockaddrBytes(int family, struct sockaddr_storage* ss) {
    if (family == AF_INET) {
        struct sockaddr_in *ss4 =(struct sockaddr_in*) ss;
        return (uint8_t*) &ss4->sin_addr;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *ss6 =(struct sockaddr_in6*) ss;
        return (uint8_t*) &ss6->sin6_addr;
    }

    return NULL;
}

// Sadly, we can't keep the interface index for portability with BSD.
// We'll have to keep the name instead, and re-query the index when
// we need it later.
bool ifa_setNameAndFlagsByIndex(ifaddrs *self, int interfaceIndex) {
    // Get the name.
    char buf[IFNAMSIZ];
    char* name = if_indextoname(interfaceIndex, buf);
    int fd = -1;
    if (name == NULL) {
        return false;
    }
    self->ifa_name = malloc(strlen(name) + 1);
    strcpy(self->ifa_name, name);

    // Get the flags.
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        goto err_out;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, name);
    int rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (rc == -1) {
        goto err_out;
    }
    self->ifa_flags = ifr.ifr_flags;
    close(fd);
    return true;
err_out:
    close(fd);
    return false;
}

// Netlink gives us the address family in the header, and the
// sockaddr_in or sockaddr_in6 bytes as the payload. We need to
// stitch the two bits together into the sockaddr that's part of
// our portable interface.
void ifa_setAddress(struct ifaddrs *self, int family, void* data, size_t byteCount) {
    // Set the address proper...
    struct sockaddr_storage* ss = malloc(sizeof(struct sockaddr_storage));
    memset(ss, 0, sizeof(*ss));
    self->ifa_addr = (struct sockaddr*) ss;
    ss->ss_family = family;
    uint8_t* dst = sockaddrBytes(family, ss);
    memcpy(dst, data, byteCount);
}

// Netlink gives us the prefix length as a bit count. We need to turn
// that into a BSD-compatible netmask represented by a sockaddr*.
void ifa_setNetmask(ifaddrs *self, int family, size_t prefixLength) {
    // ...and work out the netmask from the prefix length.
    struct sockaddr_storage* ss =  malloc(sizeof(struct sockaddr_storage));
    memset(ss, 0, sizeof(*ss));
    self->ifa_netmask = (struct sockaddr*) ss;
    ss->ss_family = family;
    uint8_t* dst = sockaddrBytes(family, ss);
    memset(dst, 0xff, prefixLength / 8);
    if ((prefixLength % 8) != 0) {
        dst[prefixLength/8] = (0xff << (8 - (prefixLength % 8)));
    }
}

// FIXME: use iovec instead.
struct addr_request {
    struct nlmsghdr netlinkHeader;
    struct ifaddrmsg msg;
};

static inline ssize_t recvNetlinkMessage(int sock, void *buf, size_t len) {
  ssize_t recvd;

  do {
        recvd = recv(sock, buf, len, 0);
  } while (recvd == -1 && errno == EINTR);

  return recvd;
}


// Source-compatible with the BSD function.
int getifaddrs(ifaddrs** result)
{
    // Simplify cleanup for callers.
    *result = NULL;

    // Create a netlink socket.
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (fd < 0) {
       return -1;
    }

    // Ask for the address information.
    struct addr_request addrRequest;
    memset(&addrRequest, 0, sizeof(addrRequest));
    addrRequest.netlinkHeader.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    addrRequest.netlinkHeader.nlmsg_type = RTM_GETADDR;
    addrRequest.netlinkHeader.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(addrRequest)));
    addrRequest.msg.ifa_family = AF_UNSPEC; // All families.
    addrRequest.msg.ifa_index = 0; // All interfaces.

    ssize_t sentByteCount;
    do {
        sentByteCount = send(fd, &addrRequest, addrRequest.netlinkHeader.nlmsg_len, 0);
    } while (sentByteCount == -1 && errno == EINTR);

    if (!(sentByteCount == (ssize_t) addrRequest.netlinkHeader.nlmsg_len)) {
        close(fd);
        return -1;
    }

    const size_t size_of_buffer = 65536;
    // Read the responses.
    char buf[size_of_buffer];
    ssize_t bytesRead;

    while ((bytesRead  = recvNetlinkMessage(fd, buf, size_of_buffer)) > 0) {
        struct nlmsghdr* hdr = (struct nlmsghdr*) buf;
        for (; NLMSG_OK(hdr, (size_t)bytesRead); hdr = NLMSG_NEXT(hdr, bytesRead)) {
            switch (hdr->nlmsg_type) {
            case NLMSG_DONE:
                goto success;
            case NLMSG_ERROR:
                goto err_out;
            case RTM_NEWADDR:
                {
                    struct ifaddrmsg* address = (struct ifaddrmsg*)(NLMSG_DATA(hdr));
                    struct rtattr* rta = IFA_RTA(address);
                    size_t ifaPayloadLength = IFA_PAYLOAD(hdr);
                    while (RTA_OK(rta, ifaPayloadLength)) {
                        if (rta->rta_type == IFA_LOCAL) {
                            int family = address->ifa_family;
                            if (family == AF_INET || family == AF_INET6) {
                                ifaddrs *next = *result;
                                *result = malloc(sizeof(ifaddrs));
                                memset(*result, 0, sizeof(ifaddrs));
                                (*result)->ifa_next = next;
                                if (!ifa_setNameAndFlagsByIndex(*result, address->ifa_index)) {
                                    goto err_out;
                                }
                                ifa_setAddress(*result, family, RTA_DATA(rta), RTA_PAYLOAD(rta));
                                ifa_setNetmask(*result, family, address->ifa_prefixlen);
                            }
                        }
                        rta = RTA_NEXT(rta, ifaPayloadLength);
                    }
                }
                break;
            }
        }
    }
err_out:
    close(fd);
    return -1;
success:
    close(fd);
    return 0;
}

// Source-compatible with the BSD function.
void freeifaddrs(ifaddrs* addresses) {
    ifaddrs* self = addresses;
    while (self != NULL) {
        free(self->ifa_name);
        free(self->ifa_addr);
        free(self->ifa_netmask);
        ifaddrs* next = self->ifa_next;
        free(self);
        self = next;
    }
}
