/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// -----------------------------------------------------------------------
bool Proxy::parseAddress(
    IPAddr      *addr,
    TCPPort     *port,
    const char  *istr
)
{
    char *p;
    char *str = p = strdup(istr);
    while(p[0]!=0 && p[0]!=':') ++p;

    if(p[0]==0) *port = 1723;
    else
    {
        *(p++) = 0;
        if(1!=sscanf(p, "%d", port))
        {
            FAIL(
                false,
                0,
                "address %s:%s has an invalid port",
                str,
                p
            );
            free(str);
            return false;
        }
    }

    *port = htons((uint16_t)*port);
    bool ret = resolve(addr, str, false);
    free(str);
    return ret;
}

// -----------------------------------------------------------------------
void Proxy::addProxyPair(
    char *argv
)
{
    if(argv==0) FAIL(true, 0, "empty argument for --proxy");
    DBG("trying to add proxy pair %s", argv);

    char *p = argv;
    while(p[0]!=0 && p[0]!=',') ++p;

    char *peer;
    char *listen;
    if(p[0]==0)
    {
        listen = strdup("0.0.0.0:1723");
        peer = argv;
    }
    else
    {
        listen = argv;
        peer = p+1;
        p[0] = 0;
    }

    IPAddr listenAddr;
    TCPPort listenPort;
    if(parseAddress(&listenAddr, &listenPort, listen)==false)
    {
        FAIL(
            false,
            0,
            "specified pair %s -> %s will be ignored because listen address can not be resolved.",
            listen,
            peer
        );
        return;
    }

    IPAddr peerAddr;
    TCPPort peerPort;
    if(parseAddress(&peerAddr, &peerPort, peer)==false)
    {
        FAIL(
            false,
            0,
            "specified pair %s -> %s will be ignored because peer address can not be resolved.",
            listen,
            peer
        );
        return;
    }

    int n = pairs.size();
    for(int i=0; i<n; ++i)
    {
        IPAddr addr = pairs[i]->getListenAddr();
        TCPPort port = pairs[i]->getListenPort();
        if(
            listenPort==port        &&
            (
                addr==listenAddr    ||
                listenAddr==0       ||
                addr==0
            )
        )
        {
            FAIL(
                false,
                0,
                "pair %s -> %s will be ignored because it conflicts with previously specified pair %s -> %s",
                listen,
                peer,
                pairs[i]->getListenName(),
                pairs[i]->getPeerName()
            );
            return;
        }
    }

    if(isDebugOn())
    {
        DBG(
            "success: adding proxy pair %s:%d ---> %s:%d",
            ipToStr(listenAddr).c_str(),
            ntohs(listenPort),
            ipToStr(peerAddr).c_str(),
            ntohs(peerPort)
        );
    }

    Pair *pair = new Pair(
        this,
        listen,
        listenAddr,
        listenPort,
        peer,
        peerAddr,
        peerPort
    );

    if(0<=pair->getSocket()) pairs.push_back(pair);
    else
    {
        FAIL(false, "couldn't build socket. tearing down pair");
        delete pair;
    }
}

// -----------------------------------------------------------------------
Proxy::Pair::Pair(
    Proxy       *_proxy,
    const char  *_listenStr,
    IPAddr      _listenAddr,
    TCPPort     _listenPort,
    const char  *_peerStr,
    IPAddr      _peerAddr,
    TCPPort     _peerPort
)
{
    socket = -1;
    proxy = _proxy;

    listenStr = _listenStr;
    listenAddr = _listenAddr;
    listenPort = _listenPort;

    peerStr = _peerStr;
    peerAddr = _peerAddr;
    peerPort = _peerPort;

    int s = proxy->makeSocket(SOCK_STREAM, 0, false);
    if(s<0)
    {
        proxy->FAIL(
            false,
            0,
            "couldn't make socket to listen on %s",
            listenStr
        );
        return;
    }

    if(proxy->setNonBlocking(s, true, false)==false)
    {
        proxy->FAIL(
            false,
            0,
            "couldn't set non blocking flag on listen socket %s",
            listenStr
        );
        close(s);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = (uint16_t)listenPort;
    addr.sin_addr.s_addr = listenAddr;
    if(bind(s,(struct sockaddr*)&addr,sizeof(addr))<0)
    {
        proxy->FAIL(
            false,
            "bind",
            "couldn't bind to %s",
            listenStr
        );
        close(s);
        return;
    }

    if(listen(s,100)<0)
    {
        proxy->FAIL(
            false,
            "listen",
            "couldn't listen on %s",
            listenStr
        );
        close(s);
        return;
    }

    socket = s;
}

// -----------------------------------------------------------------------
Proxy::Pair::~Pair()
{
    close(socket);
}

