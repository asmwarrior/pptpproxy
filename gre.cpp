/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// -----------------------------------------------------------------------
#if defined(__CYGWIN__)
    #define IP_HDRINCL 2
#endif

#ifndef IPPROTO_GRE
    #define IPPROTO_GRE 47
#endif

#if !defined(SOL_IP)
    #define SOL_IP 0
#endif

// -----------------------------------------------------------------------
void Proxy::greThread()
{
    DBG("GRE thread: up and running -- waiting for GRE packets");

    uint8_t buf[4100];
    while(1)
    {
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        memset(&from, 0, fromLen);

        int n = recvfrom(
            greSocket,
            buf,
            4096,   // TODO: ought to sniff MTU here instead of assuming
            0,
            (struct sockaddr*)&from,
            &fromLen
        );

        if(n<0)
        {
                 if(errno==EINTR)   continue;
            else if(errno==EAGAIN)  continue;
            else
            {
                FAIL(false, "recvfrom", "recvfrom failed on GRE socket");
                break;
            }
        }

        DBG("GRE thread: received GRE data packet");

        ssize_t savedN = n;
        uint8_t *packet = buf;
        if((buf[0]&0xF0)==0x40)
        {
            int headerSize = (buf[0]&0x0F)*4;
            packet += headerSize;
            n -= headerSize;
        }

        uint32_t dst;
        uint32_t src = from.sin_addr.s_addr;
        uint32_t callId = packet[6] | (((uint32_t)packet[7])<<8);

        DBG(
            "GRE thread: GRE data packet from %s, callId = 0x%X",
            ipToStr(src).c_str(),
            callId
        );

        if(isPacketDumpOn())
        {
            DBG("GRE thread: GRE packet dump follows, length = %d", savedN);
            dumpPacket(buf, savedN);
        }

        uint32_t out;
        CallId realCallId;
        int dstSocket = -1;
        bool found = findPeer(&dst, &realCallId, src, callId, &dstSocket, &out);
        if(found==false) FAIL(false, 0, "GRE thread: peer not found, dropping packet");
        else
        {
            struct sockaddr_in to;
            socklen_t toLen = sizeof(to);
            memset(&to, 0, toLen);
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = dst;
	    //to.sin_port = IPPROTO_GRE; according to raw(7), but doesn't work

            DBG(
                "GRE thread: GRE data packet peer is at %s, realCallId = 0x%X",
                ipToStr(dst).c_str(),
                realCallId
            );

            packet[6] = (realCallId>>0)&0xFF;
            packet[7] = (realCallId>>8)&0xFF;

            DBG(
                "GRE thread: GRE data packet callId patched from 0x%X to 0x%X",
                callId,
                realCallId
            );

            if(0<=dstSocket)
            {
                DBG("GRE thread: peer supports PPTP-IN-TCP, wrapping GRE data packet into TCP packet");

                uint8_t wrappedPacket[8192];
                memcpy(wrappedPacket + 8, packet, n);

                n += 8;
                wrappedPacket[0] = (n&0xFF);
                wrappedPacket[1] = (n>>8);
                wrappedPacket[2] = 0x00;
                wrappedPacket[3] = 0x01;
                wrappedPacket[4] = 0x1B;
                wrappedPacket[5] = 0x2C;
                wrappedPacket[6] = 0x3D;
                wrappedPacket[7] = 0x4E;

                uint8_t *p = wrappedPacket;
                while(n>0)
                {
                    int s = write(dstSocket, p, n);
                    if(0<=s)
                    {
                        p += s;
                        n -= s;
                    }
                    else
                    {
                             if(errno==EINTR)   continue;
                        else if(errno==EAGAIN)  continue;
                        else
                        {
                            FAIL(false, "write", "write failed on TCP socket");
                            break;
                        }
                    }
                }
            }
            else
            {
                DBG(
                    "GRE thread: forwarding GRE data packet from %s to %s via interface %s\n",
                    ipToStr(src).c_str(),
                    ipToStr(dst).c_str(),
                    ipToStr(out).c_str()
                );

                ((uint16_t*)(buf+ 2))[0] = savedN;  // reset id
                ((uint16_t*)(buf+ 4))[0] = 0;       // reset id
                ((uint16_t*)(buf+10))[0] = 0;       // reset checksum
                ((uint32_t*)(buf+12))[0] = out;     // set expected source
                ((uint32_t*)(buf+16))[0] = dst;     // set destination

                int count = sendto(
                    greSocket,
                    buf,
                    savedN,
                    0,
                    (const sockaddr*)&to,
                    toLen
                );
                if(count!=savedN)
                {
                    FAIL(false, "sendto", "sendto failed on GRE socket");
                    break;
                }
            }
        }
    }
}

// -----------------------------------------------------------------------
void *Proxy::threadHead(
    void    *vp
)
{
    Proxy *proxy = (Proxy*)vp;
    proxy->greThread();
    return 0;
}

// -----------------------------------------------------------------------
void Proxy::startGREThread()
{
    int on = 1;
    int solip = SOL_IP;
    int s = makeSocket(SOCK_RAW, IPPROTO_GRE, true);
    int r = setsockopt(s, solip, IP_HDRINCL, &on, sizeof(on));
    if(r<0)
    {
        FAIL(
            false,
            "setsockopt",
            "setsockopt(SOL_IP, IP_HDRINCL) failed on GRE socket"
        );
        FAIL(
            false,
            0,
            "this will probably not work with aliased interfaces"
        );
    }

    setNonBlocking(s, false, true);
    DBG("GRE socket sucessfully created (descriptor = %d)", s);
    greSocket = s;

    pthread_t thread;
    DBG("launching GRE thread");
    r = pthread_create(&thread, 0, threadHead, this);
    if(r<0) FAIL(true, "pthread_create", "couldn't start GRE thread");
}

