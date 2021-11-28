/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>

// -----------------------------------------------------------------------
void Proxy::addACL(
    char *acl
)
{
    if(acl==0) FAIL(true, 0, "empty argument for --acl");
    DBG("trying to add acl %s", acl);

    const char *orig = acl;
    char *p = acl = strdup(acl);
    while(p[0]!=0 && p[0]!='/') ++p;
    if(p[0]==0) FAIL(true, 0, "%s: incorrect acl syntax, should be net/mask", orig);
    p[0] = 0;

    IPAddr snet;
    bool ok = resolve(&snet, acl, false);
    if(ok==false) FAIL(true, 0, "couldn't resolve subnet %s in acl %s", p+1, orig);

    IPAddr mask;
    ok = resolve(&mask, p+1, false);
    if(ok==false) FAIL(true, 0, "couldn't resolve subnet mask %s in acl %s", p+1, orig);

    DBG(
        "success, adding acl %s = %s/%s",
        orig,
        ipToStr(snet).c_str(),
        ipToStr(mask).c_str()
    );

    acls.push_back(snet);
    acls.push_back(mask);
    free(acl);
}

// -----------------------------------------------------------------------
void Proxy::addACLCommand(
    char *cmd
)
{
    if(cmd==0) FAIL(true, 0, "empty argument for --aclCmd");
    DBG("adding aclCmd %s", cmd);
    aclCmds.push_back(cmd);
}

// -----------------------------------------------------------------------
bool Proxy::checkACL(
    IPAddr ip
)
{
    DBG(
        "checking ip %s against access control list",
        ipToStr(ip).c_str()
    );

    int n = acls.size();
    for(int i=0; i<n; i+=2)
    {
        IPAddr snet = acls[i+0];
        IPAddr mask = acls[i+1];
        if((ip&mask)==(snet&mask))
        {
            DBG(
                "found matching acl %s/%s ==> ip %s authorized.",
                ipToStr(snet).c_str(),
                ipToStr(mask).c_str(),
                ipToStr(ip).c_str()
            );
            return true;
        }
    }

    DBG(
        "standard acl failed. Checking ip %s against cmd acl",
        ipToStr(ip).c_str()
    );

    n = aclCmds.size();
    for(int j=0; j<n; ++j)
    {
        char buffer[8192];
        const char *cmd = aclCmds[j];
        snprintf(buffer, 8190, "%s %s",cmd, ipToStr(ip).c_str());

        DBG(
            "checking ip %s against cmd %s",
            ipToStr(ip).c_str(),
            buffer
        );

        int ret = system(buffer);
        int exitStatus = WEXITSTATUS(ret);

        DBG(
            "command returned %d (IP %s is %s)",
            exitStatus,
            ipToStr(ip).c_str(),
            exitStatus==0 ? "ok" : "denied"
        );
        if(exitStatus==0) return true;
    }

    return false;
}

