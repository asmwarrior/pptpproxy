/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>

// -----------------------------------------------------------------------
Proxy::CallId Proxy::allocCalleeId()
{
    calleeIdPool += 2;
    return calleeIdPool;
}

// -----------------------------------------------------------------------
Proxy::CallId Proxy::allocCallerId()
{
    callerIdPool += 2;
    return callerIdPool;
}

