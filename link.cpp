/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// -----------------------------------------------------------------------
Proxy::Link::Link(
    Proxy *_proxy,
    int   pairIndex
)
    :

        pair(_proxy->pairs[pairIndex]),
        proxy(_proxy),

        callerIP(~0),
        callerSocket(-1),
        realCallerId(~0),
        fakeCallerId(~0),
        callerCanWrap(false),
        callerReceivingIP(~0),

        calleeIP(~0),
        calleeSocket(-1),
        realCalleeId(~0),
        fakeCalleeId(~0),
        calleeCanWrap(false)
{

    DBGP(
        "incoming connection on interface %s",
        getListenName()
    );

    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    int listenSocket = pair->getSocket();
    int tmpSocket = accept(listenSocket,(struct sockaddr*)&addr, &addrLen);
    if(tmpSocket<0)
    {
        proxy->FAIL(
            false,
            "accept",
            "accept failed on listen socket for pair %s -> %s",
            getListenName(),
            getPeerName()
        );
        return;
    }

    callerIP = (IPAddr)addr.sin_addr.s_addr;
    callerName = proxy->ipToStr(callerIP);
    if(proxy->checkACL(callerIP)==false)
    {
        proxy->FAIL(
            false,
            0,
            "unauthorized connection from IP %s",
            getCallerName()
        );
        close(tmpSocket);
        return;
    }

    if(proxy->setNonBlocking(tmpSocket, true, false)==false)
    {
        proxy->FAIL(
            false,
            "connect",
            "setNonBlocking failed on caller socket for link %s -> %s",
            getCallerName(),
            getPeerName()
        );
        close(tmpSocket);
        return;
    }

    addrLen = sizeof(addr);
    int r = getsockname(tmpSocket, (struct sockaddr*)&addr, &addrLen);
    if(r<0)
    {
        proxy->FAIL(
            false,
            "getsockname",
            "getsockname failed on caller socket for link %s -> %s",
            getCallerName(),
            getPeerName()
        );
        close(tmpSocket);
        return;
    }

    callerSocket = tmpSocket;
    callerReceivingIP = (IPAddr)addr.sin_addr.s_addr;
    DBGP("callee connected on local IP %s\n",  proxy->ipToStr(callerReceivingIP).c_str());

    DBGP("connecting to peer %s", getPeerName());

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = pair->getPeerAddr();
    addr.sin_port = (uint16_t)pair->getPeerPort();

    tmpSocket = proxy->makeSocket(SOCK_STREAM, 0, false);
    if(connect(tmpSocket, (struct sockaddr*)&addr, sizeof(addr))<0)
    {
        proxy->FAIL(
            false,
            "connect",
            "failed to connect to server %s",
            getPeerName()
        );
        close(callerSocket);
        callerSocket = -1;
        close(tmpSocket);
        return;
    }

    if(proxy->setNonBlocking(tmpSocket, true, false)==false)
    {
        proxy->FAIL(
            false,
            "connect",
            "setNonBlocking failed on callee socket for link %s -> %s",
            getCallerName(),
            getPeerName()
        );
        close(callerSocket);
        callerSocket = -1;
        close(tmpSocket);
        return;
    }

    calleeIP = pair->getPeerAddr();
    calleeSocket = tmpSocket;

    DBGP(
        "tcp link established %s -> %s",
        getCallerName(),
        getPeerName()
    );

    proxy->INFO(
        "new proxy connection from %s to %s (request received on interface %s)",
        getCallerName(),
        getPeerName(),
        getListenName()
    );
}

// -----------------------------------------------------------------------
Proxy::Link::~Link()
{
    bool ok = (0<=callerSocket && 0<=calleeSocket);
    if(ok==false)
    {
        DBGP("tearing down stillborn link.");
    }
    else
    {
        DBGP(
            "tearing down link %s -> %s",
            getCallerName(),
            getPeerName()
        );
    }
    close(callerSocket);
    close(calleeSocket);

    proxy->INFO(
        "end proxy connection from %s to %s",
        getCallerName(),
        getPeerName()
    );
}

// -----------------------------------------------------------------------
bool Proxy::Link::tcpPacket(
    bool callerPacket
)
{
    int src = getCalleeSocket();
    int dst = getCallerSocket();
    if(callerPacket)
    {
        int t = src;
        src = dst;
        dst = t;
    }

    uint8_t buf[4096];
    int n = read(src, buf, 4096);
    if(n==0)
    {
        DBGP(
            "EOF condition on control socket for link %s -> %s",
            proxy->ipToStr(callerIP).c_str(),
            pair->getPeerName()
        );
        return false;
    }
    else if(n<0)
    {
        if(errno==EINTR) return true;
        if(errno==EAGAIN) return true;
        proxy->FAIL(
            false,
            "read",
            "tcp read failed on control socket for link %s -> %s",
            proxy->ipToStr(callerIP).c_str(),
            pair->getPeerName()
        );
        return false;
    }

    DBGP(
        "incoming tcp packet, type 0x%X on link %s %s %s",
        buf[9],
        proxy->ipToStr(callerIP).c_str(),
        callerPacket ? "->" : "<-",
        pair->getPeerName()
    );
    proxy->dumpPacket(buf, n);

    if(
        buf[2]==0x00    &&      // Control packet
        buf[3]==0x01    &&
        buf[4]==0x1B    &&      // Magic
        buf[5]==0x2C    &&
        buf[6]==0x3D    &&
        buf[7]==0x4E
    )
    {
        DBGP("tcp packet: PPTP-IN-TCP packet");

        if(proxy->isWrapAllowed()==false)
        {
            proxy->FAIL(
                false,
                "dropping link: wrapping disabled, but peer insists on sending wrapped packets !"
            );
            return false;
        }

        if(callerPacket==true && callerCanWrap==false)
        {
            proxy->FAIL(
                false,
                "dropping link: PPTP-IN-TCP packet from caller, but caller can't wrap !"
            );
            return false;
        }

        if(callerPacket==false && calleeCanWrap==false)
        {
            proxy->FAIL(
                false,
                "dropping link: PPTP-IN-TCP packet from callee, but callee can't wrap !"
            );
            return false;
        }

        if(
            (callerPacket==true  && calleeCanWrap==false)    ||
            (callerPacket==false && callerCanWrap==false)
        )
        {
            uint8_t *grePacket = 8 + buf;
        }
    }
    else if(
        buf[2]==0x00    &&      // Control packet
        buf[3]==0x01    &&
        buf[4]==0x1A    &&      // Magic
        buf[5]==0x2B    &&
        buf[6]==0x3C    &&
        buf[7]==0x4D
    )
    {
        if(
	    buf[8]==0x00        &&
	    (
	        buf[9]==0x01    ||    // Start control connection request
	        buf[9]==0x02          // Start control connection reply
            )
        )
	{
            DBGP(
                "start of control connection %s",
                buf[9]==0x01 ? "request" : "reply"
            );

            uint8_t *p = 92+buf;
            static const char marker[] = "PPTP-IN-TCP";
            if(n<156)
	    {
                int delta = 156-n;
                memset(n+buf, 0, delta);
                n = 156;
            }

            if(0==strcmp((const char*)p, marker))
	    {
                DBGP(
                    "%s has PPTP-IN-TCP marker",
                    callerPacket ? "caller" : "callee"
                );

                if(proxy->isWrapAllowed()==true)
                {
                    if(callerPacket)    callerCanWrap = true;
                    else                calleeCanWrap = true;
                }
            }

            if(proxy->isWrapAllowed()==true)
            {
                DBGP(
                    "adding PPTP-IN-TCP marker to packet before forwarding to %s",
                    callerPacket ? "callee" : "callee"
                );
                strcpy((char*)p, marker);
            }
	}
        else if(
            buf[8]==0x00        &&
            (
                buf[9]==0x07    ||      // Outgoing Call request
                buf[9]==0x08
            )
        )
        {
            uint32_t fakeId;
            uint32_t id = buf[12] | (((uint16_t)buf[13])<<8);
            uint32_t serial = buf[14] | (((uint16_t)buf[15])<<8);
            if(callerPacket)
            {
                realCallerId = id;
                fakeCallerId = fakeId = proxy->allocCallerId();
            }
            else
            {
                realCalleeId = id;
                fakeCalleeId = fakeId = proxy->allocCalleeId();
            }
            buf[12] = (fakeId>>0)&0xFF;
            buf[13] = (fakeId>>8)&0xFF;

            DBGP(
                "id remapping complete: realCallId = 0x%X, fakeCallId = 0x%X %s = 0x%X",
                id,
                fakeId,
                buf[9]==0x08 ? "peerId" : "serial",
                serial
            );

            if(buf[9]==0x08)
            {
                CallId peer = realCallerId;
                buf[14] = (peer>>0)&0xFF;
                buf[15] = (peer>>8)&0xFF;
            }
        }
        else if(
            buf[8]==0x00        &&
            (
                buf[9]==0x0C    ||      // Call-Clear-Request
                buf[9]==0x0D    ||      // Call-Disconnect-Notify
                buf[9]==0x0E    ||      // WAN-Error-Notify
                buf[9]==0x0F            // Set-Link_Info
            )
        )
        {
            uint32_t mappedId;
            uint32_t id = buf[12] | (((uint16_t)buf[13])<<8);
            if(proxy->remapId(&mappedId, id))
            {
                buf[12] = (mappedId>>0)&0xFF;
                buf[13] = (mappedId>>8)&0xFF;
            }
        }
    }

    DBGP("forwarding tcp packet\n");

    uint8_t *p = buf;
    while(n>0)
    {
        int s = write(dst, p, n);
        if(s==0)
        {
            proxy->FAIL(
                false,
                0,
                "wrote 0 bytes on control socket for pair %s -> %s",
                pair->getListenName(),
                pair->getPeerName()
            );
            return false;
        }
        else if(s>0)
        {
            p+=s;
            n-=s;
        }
        else
        {
            if(errno==EINTR)            continue;
            else if(errno==EAGAIN)      continue;
            else
            {
                proxy->FAIL(
                    false,
                    "write",
                    "tcp write failed on control socket for pair %s -> %s",
                    pair->getListenName(),
                    pair->getPeerName()
                );
                return false;
            }
        }
    }

    return true;
}

