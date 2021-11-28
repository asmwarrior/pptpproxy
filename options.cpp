/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <proxy.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <version.h>

// -----------------------------------------------------------------------
static void help(
    bool doExit = true
)
{
    printf(
        "\n"
        "Usage: pptpproxy [options]\n"
        "\n"
        "    Options:\n"
        "\n"
        "        -h, --help                     Print help\n"
        "        -d, --debug                    Debug mode\n"
        "        -n, --nofork                   Run in the foreground\n"
        "        -v, --version                  Print version and exit\n"
        "        -f, --forceStd                 Do not initiate nor accept pptp-in-tcp extension\n"
        "        -e, --extensive                Dump all packets seen\n"
        "        -l, --log logFile              Log output to logFile\n"
        "        -c, --codeLocDebug             Include code locations in debug output\n"
        "        -a, --acl subnet/mask          Add subnet to access control list.\n"
        "        -x, --aclCmd external command  Launch an external command to verify ACL\n"
        "\n"
        "        -p, --proxy [listen[:listenPort],]remote[:remotePort]\n"
        "\n"
        "           Forwards incoming PPTP connections received on TCP address\n"
        "           <listen:listenPort> to remote PPTP server <remote:remotePort>.\n"
        "\n"
        "    Example:\n"
        "\n"
        "           pptpproxy -p pptpserver.mycompany.com\n"
        "\n"
    );
    if(doExit) exit(0);
}

// -----------------------------------------------------------------------
static void version()
{
    printf(
        "\n"
        "pptpproxy version %s\n"
        "written by Emmanuel Mogenet<mgix@mgix.com>\n",
        PPTPPROXY_VERSION
    );
}

// -----------------------------------------------------------------------
void Proxy::options(
    char **argv
)
{
    version();

    while(1)
    {
        const char *arg = *++argv;

             if(arg==0)                                                 break;
        else if(0==strcmp(arg,"-h") || 0==strcmp(arg,"--help"))         help();
        else if(0==strcmp(arg,"-v") || 0==strcmp(arg,"--version"))      exit(0);
        else if(0==strcmp(arg,"-d") || 0==strcmp(arg,"--debug"))        debug = true;
        else if(0==strcmp(arg,"-f") || 0==strcmp(arg,"--forceStd"))     wrap = false;
        else if(0==strcmp(arg,"-n") || 0==strcmp(arg,"--nofork"))       noFork = true;
        else if(0==strcmp(arg,"-c") || 0==strcmp(arg,"--codeLocDebug")) codeDebug = true;
        else if(0==strcmp(arg,"-e") || 0==strcmp(arg,"--extensive"))    packetDump = true;
        else if(0==strcmp(arg,"-a") || 0==strcmp(arg,"--acl"))          addACL(argv ? *++argv : 0);
        else if(0==strcmp(arg,"-l") || 0==strcmp(arg,"--log"))          logFile = (argv ? *++argv : 0);
        else if(0==strcmp(arg,"-p") || 0==strcmp(arg,"--proxy"))        addProxyPair(argv ? *++argv : 0);
        else if(0==strcmp(arg,"-x") || 0==strcmp(arg,"--exec"))         addACLCommand(argv ? *++argv : 0);
        else
        {
            FAIL(false, 0, "unknown argument %s", *argv);
            help();
        }
    }

    if(isPacketDumpOn()) debug = true;
    if(isDebugOn()) noFork = true;

    if(aclCmds.size()<=0 && acls.size()<=0)
    {
        DBG("no acl specified, forcing 0/0 (all allowed)");
        addACL("0/0");
    }

    if(pairs.size()<=0)
    {
        help(false);
        FAIL(false, 0, "please specify at least one pair with -p.");
        FAIL(true, 0, "no valid proxy pair specified.");
    }
}

