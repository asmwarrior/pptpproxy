#!/usr/bin/perl

# This file is part of pptpproxy
# and is in the public domain

use strict;
use warnings;
use File::Basename;

my($show) = 0;
my($debug) = 0;
my($target) = 'pptpproxy';
if(defined($ARGV[0]))
{
    if($ARGV[0] eq 'show')
    {
        shift(@ARGV);
        $show = 1;
    }
    elsif($ARGV[0] eq 'debug')
    {
        shift(@ARGV);
        $debug = 1;
    }
}

my(@sources) = qw(
    acl.cpp
    db.cpp
    fake.cpp
    gre.cpp
    link.cpp
    log.cpp
    main.cpp
    options.cpp
    pairs.cpp
    proxy.cpp
    server.cpp
    utils.cpp
);

my($verbose) = 1;
my($allArgs) = join(' ', @ARGV);
if($show)
{
    open(Z, ">&=1") or die "Cannot reopen fd=0: $!";
}
else
{
    open(Z, "| /usr/bin/make -f - -r -k -j2 $allArgs");
}

my($header)='';
$header = <<'EOF';

CPLUS = c++
SHELL=/bin/sh

INC =                                   \
        -I.                             \

COPT =                                  \
        -g0                             \
        -O6                             \
        -Winline                        \
        -fno-check-new                  \
        -fno-exceptions                 \
        -fomit-frame-pointer            \
        -fexpensive-optimizations       \

LOPT =                                  \


LIBS =                                  \
        -lpthread                       \

EOF

if($debug)
{
    $header =~ s/-g0/-O0/;
    $header =~ s/-O6/-g3 -fno-inline/;
    $header =~ s/-funroll-loops//g;
    $header =~ s/-fno-exceptions//g;
    $header =~ s/-fomit-frame-pointer//g;
    $header =~ s/-fexpensive-optimizations//g;
}

print Z <<"EOF";

$header

all:$target

EOF

my($src);
my($objs) = '';
my($lobjs) = '';
my($s) = ($verbose ? '' : '@');
my($strip) = ($debug ? '' : "\@strip $target");
foreach $src (@sources)
{
    $src =~ s/[ \t\r\n]+//g;
    next if(length($src)==0);

    my($base, $path) = File::Basename::fileparse($src);
    my($savedBase) = $base;
    $base =~ s/\.cpp$//;
    $base =~ s/\.c$//;

    my($obj) = ".objs/$base.o";
    $objs .= "    $obj\\\n";

    print Z "$obj : $src\n";
    print Z "\t\@mkdir -p .deps\n";
    print Z "\t\@mkdir -p .objs\n";
    if($src=~/\.c$/)
    {
        print Z "\t\@echo cc -- $savedBase\n" unless($verbose);
        print Z "\t$s\${CC} -MD \${INC} \${COPT} -c $src -o $obj\n";
    }
    else
    {
        print Z "\t\@echo c++ -- $savedBase\n" unless($verbose);
        print Z "\t$s\${CPLUS} -MD \${INC} \${COPT} -c $src -o $obj\n";
    }
    print Z "\t\@mv .objs/$base.d .deps\n";
    print Z "\n";
}

my($v) = ($verbose ? '>/dev/null 2>/dev/null' : '');
print Z <<"EOF";

OBJS=\\
$objs

$target:\${OBJS}
	\@echo lnk -- $target $v
	$s\${CPLUS} \${LOPT} \${COPT} -o $target \${OBJS} \${LIBS}
	$s$strip
clean:
	-rm -rf $target core.* .gdb* .objs .deps *.d *.o *.i *stackdump* gmon.out pptpproxy.exe

-include .deps/*

EOF

close(Z);

