/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

// -----------------------------------------------------------------------
void Proxy::enterDBReadOnly()
{
    pthread_mutex_lock(dbLock);
        pthread_mutex_lock(readerLock);
            ++nbReaders;
        pthread_mutex_unlock(readerLock);
    pthread_mutex_unlock(dbLock);
}

// -----------------------------------------------------------------------
void Proxy::leaveDBReadOnly()
{
    pthread_mutex_lock(readerLock);
        --nbReaders;
    pthread_mutex_unlock(readerLock);
}

// -----------------------------------------------------------------------
void Proxy::enterDBReadWrite()
{
    pthread_mutex_lock(dbLock);

    while(1)
    {
        pthread_mutex_lock(readerLock);
            int n = nbReaders;
        pthread_mutex_unlock(readerLock);
        if(n<=0) break;
        usleep(1000);
    }
}

// -----------------------------------------------------------------------
void Proxy::leaveDBReadWrite()
{
    pthread_mutex_unlock(dbLock);
}

// -----------------------------------------------------------------------
bool Proxy::remapId(
    CallId  *mappedId,
    CallId  id
)
{
    DBG("trying to map real id 0x%X for control packet", id);

    enterDBReadOnly();

        bool success = false;
        size_t n = links.size();
        for(size_t i=0; i<n; ++i)
        {
            Link *link = links[i];
            if(id==link->getFakeCallerId())
            {
                mappedId[0] = link->getRealCallerId();
                success = true;
                break;
            }
            else if(id==link->getRealCallerId())
            {
                mappedId[0] = link->getFakeCallerId();
                success = true;
                break;
            }
            else if(id==link->getFakeCalleeId())
            {
                mappedId[0] = link->getRealCalleeId();
                success = true;
                break;
            }
            else if(id==link->getRealCalleeId())
            {
                mappedId[0] = link->getFakeCalleeId();
                success = true;
                break;
            }
        }

    leaveDBReadOnly();

    if(success==false)
    {
        FAIL(
            false,
            0,
            "failed to map id 0x%X for control packet",
            id
        );
    }
    else
    {
        DBG(
            "successfully mapped id 0x%X to fake id 0x%X for control packet",
            id,
            *mappedId
        );
    }

    return success;
}

// -----------------------------------------------------------------------
bool Proxy::findPeer(
    IPAddr  *dst,
    CallId  *realCallId,
    IPAddr  src,
    CallId  fakeCallId,
    int     *dstSocket,
    IPAddr  *sndAddr
)
{
    DBG(
        "GRE thread: trying to find peer for GRE packet, src = %s callId = 0x%X",
        ipToStr(src).c_str(),
        fakeCallId
    );

    dstSocket[0] = -1;

    enterDBReadOnly();

        bool success = false;
        int n = links.size();
        for(int i=0; i<n; ++i)
        {
            Link *link = links[i];
            if(
                fakeCallId==link->getFakeCallerId() &&
                src==link->getCalleeIP()
            )
            {
                dst[0] = link->getCallerIP();
                sndAddr[0] = link->getCallerRCVIP();
                realCallId[0] = link->getRealCallerId();
                if(link->getCallerCanWrap()==true) dstSocket[0] = link->getCallerSocket();

                DBG(
                    "GRE thread: found peer(caller) for GRE packet, src = %s dst = %s, realId = 0x%X",
                    ipToStr(src).c_str(),
                    ipToStr(*dst).c_str(),
                    realCallId[0]
                );
                success = true;
                break;
            }
            else if(
                fakeCallId==link->getFakeCalleeId() &&
                src==link->getCallerIP()
            )
            {
                sndAddr[0] = 0;
                dst[0] = link->getCalleeIP();
                realCallId[0] = link->getRealCalleeId();
                if(link->getCalleeCanWrap()==true) dstSocket[0] = link->getCalleeSocket();
                DBG(
                    "GRE thread: found peer(callee) for GRE packet, src = %s dst = %s, realId = 0x%X",
                    ipToStr(src).c_str(),
                    ipToStr(*dst).c_str(),
                    realCallId[0]
                );
                success = true;
                break;
            }
        }

    leaveDBReadOnly();

    if(success==false)
    {
        FAIL(
            false,
            0,
            "GRE thread: dropping unknown GRE packet from IP %s, fakeCallId = 0x%X",
            ipToStr(src).c_str(),
            fakeCallId
        );
    }

    return success;
}

