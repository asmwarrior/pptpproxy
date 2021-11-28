/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <pthread.h>

// -----------------------------------------------------------------------
Proxy::Proxy(
    char **argv
)
{
    wrap = true;
    info = true;
    debug = false;
    noFork = false;
    codeDebug = false;
    daemonized = false;
    packetDump = false;

    logFile = 0;
    greSocket = -1;
    calleeIdPool = 0;
    callerIdPool = 1;

    pthread_mutex_t iLock = PTHREAD_MUTEX_INITIALIZER;
    readerLock = new pthread_mutex_t(iLock);
    dbLock = new pthread_mutex_t(iLock);
    nbReaders = 0;

    options(argv);

    if(setuid(0)<0)
    {
        FAIL(false, "setuid", "setuid(0) failed, continuing without root permissions ");
        FAIL(false, 0, "however, chances are server socket creation will fail.");
    }

    daemonize();
    startGREThread();
    server();
}

// -----------------------------------------------------------------------
Proxy::~Proxy()
{
}

