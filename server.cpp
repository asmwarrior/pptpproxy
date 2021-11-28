/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

#if defined(__CYGWIN__)
    #include <sys/select.h>
#endif

// -----------------------------------------------------------------------
static inline void addSocket(
    int    socket,
    int    *max,
    fd_set *readSet,
    fd_set *exceptionSet
)
{
    if(max[0]<socket) max[0] = socket;
    FD_SET(socket,exceptionSet);
    FD_SET(socket,readSet);
}

// -----------------------------------------------------------------------
void Proxy::server()
{
    DBG("TCP thread: up and running -- waiting for inbound TCP connections");

    fd_set readSet;
    fd_set exceptionSet;
    std::vector<int> deadLinks;
    std::vector<Link*> newLinks;
    while(1)
    {
        int i;
        int n;
        int max = -1;
        FD_ZERO(&readSet);
        FD_ZERO(&exceptionSet);

        n = pairs.size();
        for(i=0; i<n; ++i)
        {
            addSocket(
                pairs[i]->getSocket(),
                &max,
                &readSet,
                &exceptionSet
            );
        }

        enterDBReadOnly();
            n = links.size();
            for(i = 0;i<n;++i)
            {
                addSocket(
                    links[i]->getCallerSocket(),
                    &max,
                    &readSet,
                    &exceptionSet
                );
                addSocket(
                    links[i]->getCalleeSocket(),
                    &max,
                    &readSet,
                    &exceptionSet
                );
            }
        leaveDBReadOnly();

        int ret = select(1+max, &readSet, 0, &exceptionSet, 0);

        if(ret<0 && errno!=EINTR && errno!=EAGAIN)
        {
            FAIL(
                false,
                "select",
                "select failed !\n"
            );
        }
        else if(0<ret)
        {
            n = pairs.size();
            for(i=0; i<n; ++i)
            {
                int s = pairs[i]->getSocket();
                if(FD_ISSET(s,&readSet))
                {
                    DBG(
                        "new link request on interface %s, proxying to %s",
                        pairs[i]->getListenName(),
                        pairs[i]->getPeerName()
                    );

                    bool newLinkOK = true;
                    Link *newLink = new Link(this,i);
                    newLinkOK = newLinkOK && newLink->getCallerSocket()>=0;
                    newLinkOK = newLinkOK && newLink->getCalleeSocket()>=0;

                    DBG(
                        "new link request on interface %s %s.",
                        pairs[i]->getListenName(),
                        newLinkOK ? "suceeded" : "failed"
                    );

                    if(newLinkOK) newLinks.push_back(newLink);
                    else          delete newLink;
                }
                if(FD_ISSET(s, &exceptionSet))
                {
                    FAIL(
                        false,
                        "select",
                        "exception on listen socket %s -> %s!\n",
                        pairs[i]->getListenName(),
                        pairs[i]->getPeerName()
                    );
                }
            }

            enterDBReadOnly();
                i = links.size();
                while(i--)
                {
                    bool linkOK = true;
                    int s1 = links[i]->getCallerSocket();
                    int s2 = links[i]->getCalleeSocket();
                    if(FD_ISSET(s1, &readSet)) linkOK = linkOK && links[i]->tcpPacket(true);
                    if(FD_ISSET(s2, &readSet)) linkOK = linkOK && links[i]->tcpPacket(false);
                    if(FD_ISSET(s1, &exceptionSet)) linkOK = false;
                    if(FD_ISSET(s2, &exceptionSet)) linkOK = false;

                    if(linkOK==false)
                    {
                        DBG(
                            false,
                            0,
                            "exception on tcp link %s -> %s.",
                            ipToStr(links[i]->getCallerIP()).c_str(),
                            links[i]->getPeerName()
                        );
                        deadLinks.push_back(i);
                    }
                }
            leaveDBReadOnly();

            int n1 = newLinks.size();
            int n2 = deadLinks.size();
            if(n1!=0 || n2!=0)
            {
                enterDBReadWrite();
                    while(n1--) links.push_back(newLinks[n1]);
                    while(n2--)
                    {
                        int i = deadLinks[n2];
                        DBG(
                            "removing links[%d] = %s -> %s",
                            i,
                            links[i]->getCallerName(),
                            links[i]->getPeerName()
                        );

                        Link *link = links[i];
                        links[i] = links[links.size()-1];
                        links.pop_back();
                        delete link;
                    }
                leaveDBReadWrite();
                deadLinks.clear();
                newLinks.clear();
            }
        }
    }
}

