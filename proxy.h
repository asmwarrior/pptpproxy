/*
 * This file is part of pptpproxy
 * and is in the public domain
 */
#ifndef __PROXY_H__
    #define __PROXY_H__

    #include <vector>
    #include <string>
    #include <cstring>
    #include <stdint.h>
    #include <stdarg.h>
    #include <stddef.h>
    #include <netinet/in.h>

    #ifndef linux
        #ifndef _SOCKLEN_T
            #ifndef __CYGWIN__
                typedef int socklen_t;
            #endif
        #endif
    #endif

    // -----------------------------------------------------------------------

    #define _PPTPFN_ __PRETTY_FUNCTION__


    #define INFO(...)           \
        nfo(                    \
            __FILE__,           \
            __LINE__,           \
            _PPTPFN_,           \
            __VA_ARGS__         \
        )                       \

    #define DBG(...)            \
    {                           \
        if(isDebugOn())         \
        {                       \
            dbg(                \
                __FILE__,       \
                __LINE__,       \
                _PPTPFN_,       \
                __VA_ARGS__     \
            );                  \
        }                       \
    }                           \

    #define DBGP(...)           \
    {                           \
        if(proxy->isDebugOn())  \
        {                       \
            proxy->dbg(         \
                __FILE__,       \
                __LINE__,       \
                _PPTPFN_,       \
                __VA_ARGS__     \
            );                  \
        }                       \
    }                           \

    #define FAIL(...)           \
        fail(                   \
            __FILE__,           \
            __LINE__,           \
            _PPTPFN_,           \
            __VA_ARGS__         \
        )                       \

    // -----------------------------------------------------------------------
    class Proxy
    {
    public:
        typedef uint32_t CallId;
        typedef uint32_t IPAddr;
        typedef uint32_t TCPPort;

        // -----------------------------------------------------------------------
        class Pair
        {
        private:
            int         socket;
            Proxy       *proxy;

            IPAddr      listenAddr;
            TCPPort     listenPort;
            const char  *listenStr;

            IPAddr      peerAddr;
            TCPPort     peerPort;
            const char  *peerStr;

        public:
            Pair(
                Proxy       *_proxy,
                const char  *_listenStr,
                IPAddr      _listenAddr,
                TCPPort     _listenPort,
                const char  *_peerStr,
                IPAddr      _peerAddr,
                TCPPort     _peerPort
            );
            ~Pair();

            int getSocket()             { return socket;        }
            IPAddr getListenAddr()      { return listenAddr;    }
            TCPPort getListenPort()     { return listenPort;    }
            IPAddr getPeerAddr()        { return peerAddr;      }
            TCPPort getPeerPort()       { return peerPort;      }
            const char *getPeerName()   { return peerStr;       }
            const char *getListenName() { return listenStr;     }
        };

        // -----------------------------------------------------------------------
        class Link
        {
        private:

            Pair    *pair;
            Proxy   *proxy;

            IPAddr  callerIP;
            int     callerSocket;
            CallId  realCallerId;
            CallId  fakeCallerId;
	    bool    callerCanWrap;
            IPAddr  callerReceivingIP;

            IPAddr  calleeIP;
            int     calleeSocket;
            CallId  realCalleeId;
            CallId  fakeCalleeId;
            bool    calleeCanWrap;

            std::string callerName;

        public:

            Link(
                Proxy   *_proxy,
                int     pairIndex
            );
            ~Link();

            bool tcpPacket(bool callerPacket);

            Pair *getPair()             { return pair;                  }
            const char *getPeerName()   { return pair->getPeerName();   }
            const char *getListenName() { return pair->getListenName(); }
            const char *getCallerName() { return callerName.c_str();    }

            IPAddr getCallerIP()        { return callerIP;              }
            int getCallerSocket()       { return callerSocket;          }
            CallId getRealCallerId()    { return realCallerId;          }
            CallId getFakeCallerId()    { return fakeCallerId;          }
            bool getCallerCanWrap()     { return callerCanWrap;         }
            IPAddr getCallerRCVIP()     { return callerReceivingIP;     }

            IPAddr getCalleeIP()        { return calleeIP;              }
            int getCalleeSocket()       { return calleeSocket;          }
            CallId getRealCalleeId()    { return realCalleeId;          }
            CallId getFakeCalleeId()    { return fakeCalleeId;          }
            bool getCalleeCanWrap()     { return calleeCanWrap;         }
        };

        // -----------------------------------------------------------------------
        bool                wrap;
        bool                info;
        bool                debug;
        bool                noFork;
        bool                codeDebug;
        bool                daemonized;
        bool                packetDump;

        const char          *logFile;
        int                 greSocket;

        CallId              calleeIdPool;
        CallId              callerIdPool;

        pthread_mutex_t     *dbLock;
        pthread_mutex_t     *readerLock;
        volatile int        nbReaders;

        std::vector<Link*>  links;
        std::vector<Pair*>  pairs;

        std::vector<IPAddr> acls;
        std::vector<char*>  aclCmds;

        // -----------------------------------------------------------------------
        void addACL(char *acl);
        bool checkACL(IPAddr ip);
        void addACLCommand(char *acl);

        bool remapId(CallId*,CallId);
        void addProxyPair(char *acl);
        bool findPeer(IPAddr*, CallId*, IPAddr, CallId, int*, IPAddr*);

        void vlog(
            const char  *fileName,
            int32_t     lineNumber,
            const char  *funcName,
            const char  *type,
            const char  *msg,
            va_list
        );

        void log(
            const char  *fileName,
            int32_t     lineNumber,
            const char  *funcName,
            const char  *type,
            const char  *msg = 0,
            ...
        );

        void nfo(
            const char  *fileName,
            int32_t     lineNumber,
            const char  *funcName,
            const char  *format = 0,
            ...
        );

        void dbg(
            const char  *fileName,
            int32_t     lineNumber,
            const char  *funcName,
            const char  *format = 0,
            ...
        );

        void fail(
            const char  *fileName,
            int32_t     lineNumber,
            const char  *funcName,
            bool        fatal,
            const char  *sys,
            const char  *msg = 0,
            ...
        );

        bool isInfoOn()         { return info;          }
        bool isDebugOn()        { return debug;         }
        bool isPacketDumpOn()   { return packetDump;    }
        bool isWrapAllowed()    { return wrap;          }

        CallId allocCalleeId();
        CallId allocCallerId();

        void greThread();
        void startGREThread();
        static void *threadHead(void*);

        void server();
        void daemonize();
        void options(char **argv);
        std::string ipToStr(IPAddr);
        void dumpPacket(uint8_t *buf, ssize_t length);
        int makeSocket(int type,int proto,bool fatal);
        bool setNonBlocking(int s,bool yes,bool fatal);
        bool parseAddress(IPAddr*,TCPPort*,const char*);
        bool resolve(IPAddr*,const char *add,bool fatal);

        void enterDBReadOnly();
        void leaveDBReadOnly();

        void enterDBReadWrite();
        void leaveDBReadWrite();

    public:
        Proxy(char **argv);
        ~Proxy();

    };

#endif // __PROXY_H__

