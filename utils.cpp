/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <proxy.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

// -----------------------------------------------------------------------
bool Proxy::resolve(
    IPAddr      *result,
    const char  *address,
    bool        fatal
)
{
    const char *p = address;
    while('0'<=p[0] && p[0]<='9') ++p;
    if(p[0]==0 && p-address<=6)
    {
        int nb = sscanf(address, "%d", result);
        if(nb==1) return true;
    }

    if(0==strcmp(address, "0.0.0.0"))
    {
        result[0] = 0;
        return true;
    }

    struct hostent *he = gethostbyname(address);
    if(he==0)
    {
        FAIL(fatal, "gethostbyname", "can't resolve IP for %s", address);
        return false;
    }
    result[0] = *(uint32_t*)&(he->h_addr)[0];
    return true;
}

// -----------------------------------------------------------------------
int Proxy::makeSocket(
    int  type,
    int  proto,
    bool fatal
)
{
    int s = socket(PF_INET, type, proto);
    if(s<0)
    {
        FAIL(
            fatal,
            "socket",
            "couldn't create socket%s",
            errno==EPERM ? " (permission denied). try to run pptpproxy as root." : ""
        );
    }

    int on = 1;
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))<0)
    {
        FAIL(
            fatal,
            "setsockopt",
            "couldn't do a setsockopt(SO_REUSEADDR) on socket"
        );
    }

    #if !defined(__CYGWIN__)
        struct linger lng;
        memset(&lng, 0, sizeof(lng));
        if(setsockopt(s, SOL_SOCKET, SO_LINGER, &lng, sizeof(lng))<0)
        {
            FAIL(
                fatal,
                "setsockopt",
                "couldn't do a setsockopt(SO_LINGER) on socket"
            );
        }
    #endif

    return s;
}

// -----------------------------------------------------------------------
void Proxy::daemonize()
{
    if(noFork==true) return;
    daemonized = true;

    if(signal(SIGHUP , SIG_IGN)<0) FAIL(true, "signal", "SIGHUP ");
    if(signal(SIGALRM, SIG_IGN)<0) FAIL(true, "signal", "SIGALRM");
    if(signal(SIGPIPE, SIG_IGN)<0) FAIL(true, "signal", "SIGPIPE");
    if(signal(SIGUSR1, SIG_IGN)<0) FAIL(true, "signal", "SIGUSR1");
    if(signal(SIGUSR2, SIG_IGN)<0) FAIL(true, "signal", "SIGUSR2");
    if(chdir("/")<0)               FAIL(true, "chdir ", "chdir(/)");

    umask(0);
    close(0);
    close(1);
    close(2);

    openlog(
        "pptpproxy",
        LOG_PID     |
        LOG_NDELAY,
        LOG_DAEMON
    );

    int childPid = fork();
    if(childPid<0) FAIL(true, "fork", "fork failed");
    else if(childPid!=0)
    {
        while(1)
        {
            int status;
            int child = waitpid(-1, &status, WNOHANG);
            if(child==-1 && errno!=EINTR && errno!=EAGAIN) FAIL(true, "waitpid", "couldn't double-fork");
            if(child!=childPid) FAIL(true, "waitpid", "waitpid returned wrong child pid");
            exit(0);
        }
    }

    childPid = fork();
    if(childPid<0)     FAIL(true, "fork", "double-fork failed");
    if(childPid!=0)    exit(0);
    setsid();
}

// -----------------------------------------------------------------------
bool Proxy::setNonBlocking(
    int     s,
    bool    yes,
    bool    fatal
)
{
    int flags = fcntl(s, F_GETFL, 0);
    if(flags<0)
    {
        FAIL(
            fatal,
            "fcntl",
            "couldn't get socket flags"
        );
        return false;
    }

    flags = yes ? (flags|O_NONBLOCK) : (flags&~O_NONBLOCK);
    if(fcntl(s, F_SETFL, flags)<0)
    {
        FAIL(
            fatal,
            "fcntl",
            "couldn't change O_NONBLOCK on socket"
        );
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------
std::string Proxy::ipToStr(
    IPAddr ip
)
{
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = ip;

    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
        std::string result(inet_ntoa(addr.sin_addr));
    pthread_mutex_unlock(&lock);
    return result;
}

// -----------------------------------------------------------------------
void Proxy::dumpPacket(
    uint8_t     *buf,
    ssize_t     length
)
{
    if(isPacketDumpOn()==false) return;
    DBG("dumping packet of length %d", length);

    uint8_t *s = buf;
    uint8_t line[256];
    while(0<length)
    {
        uint8_t *p = s;
        uint8_t *d = line;
        static const char hexa[] = "0123456789ABCDEF";
        size_t lineSize = 16<length ? 16 : length;
        for(size_t i = 0; i<lineSize; ++i)
        {
            uint8_t c = *(s++);
            d[0] = hexa[c>>4];
            d[1] = hexa[c&0xF];
            d[2] = ' ';
            d += 3;
        }

        int nbSpaces = 3 + 3*(16-lineSize);
        for(size_t i=0; i<nbSpaces; ++i) *(d++) = ' ';

        for(size_t i = 0; i<lineSize; ++i)
        {
            uint8_t c = *(p++);
            d[0] = isprint(c) ? c : '.';
            ++d;
        }

        length -=lineSize;
        d[0] = 0;

        DBG("%s", line);
    }
}

