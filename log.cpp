/*
 * This file is part of pptpproxy
 * and is in the public domain
 */

#include <errno.h>
#include <proxy.h>
#include <stdio.h>
#include <syslog.h>

// -----------------------------------------------------------------------
void Proxy::vlog(
    const char  *fileName,
    int32_t     lineNumber,
    const char  *funcName,
    const char  *type,
    const char  *format,
    va_list     arg
)
{
    FILE *f =
        logFile     ?   fopen(logFile,"a")  :
        daemonized  ?   0                   :
        stdout;

    if(f==0) vsyslog(LOG_ERR, format, arg);
    else
    {
        if(codeDebug)
        {
            fprintf(
                f,
                "pptpproxy: file %s, line %3d, function %s\n",
                fileName,
                lineNumber,
                funcName
            );
        }
        fprintf(f, "pptpproxy: %s", type);
        vfprintf(f, format, arg);
        fputc('\n',f);
        fflush(f);
        if(f!=stdout) fclose(f);
    }
}

// -----------------------------------------------------------------------
void Proxy::log(
    const char  *fileName,
    int32_t     lineNumber,
    const char  *funcName,
    const char  *type,
    const char  *format,
    ...
)
{
    va_list arg;
    va_start(arg, format);
        vlog(
            fileName,
            lineNumber,
            funcName,
            type,
            format,
            arg
        );
    va_end(arg);
}

// -----------------------------------------------------------------------
void Proxy::nfo(
    const char  *fileName,
    int32_t     lineNumber,
    const char  *funcName,
    const char  *format,
    ...
)
{
    if(isInfoOn()==false) return;

    va_list arg;
    va_start(arg, format);
        vlog(
            fileName,
            lineNumber,
            funcName,
            "info   : ",
            format,
            arg
        );
    va_end(arg);
}

// -----------------------------------------------------------------------
void Proxy::dbg(
    const char  *fileName,
    int32_t     lineNumber,
    const char  *funcName,
    const char  *format,
    ...
)
{
    if(isDebugOn()==false) return;

    va_list arg;
    va_start(arg, format);
        vlog(
            fileName,
            lineNumber,
            funcName,
            "debug  : ",
            format,
            arg
        );
    va_end(arg);
}

// -----------------------------------------------------------------------
void Proxy::fail(
    const char  *fileName,
    int32_t     lineNumber,
    const char  *funcName,
    bool        fatal,
    const char  *sys,
    const char  *format,
    ...
)
{
    const char *type = fatal ? "fatal  : " : "warning: ";

    if(sys!=0)
    {
        log(
            fileName,
            lineNumber,
            funcName,
            type,
            "%s: %s",
            sys,
            strerror(errno)
        );
    }

    if(format!=0)
    {
        va_list arg;
        va_start(arg, format);
            vlog(
                fileName,
                lineNumber,
                funcName,
                type,
                format,
                arg
            );
        va_end(arg);
    }

    if(fatal==true)
    {
        log(
            fileName,
            lineNumber,
            funcName,
            "",
            "exiting.\n"
        );
        exit(1);
    }
}

