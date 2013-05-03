#!/usr/bin/perl -w
use strict;
use warnings;
 use threads ('yield',
'stack_size' => 64*4096,
'exit' => 'threads_only',
'stringify');
$| = 1;
my $i=0;
my $i2=0;
my $thr1 = async { for ($i=0; $i<10000; $i++){ print "Thread #1 : $i\n"; sleep 1;} };
my $thr2 = async { for ($i2=0; $i2<10000; $i2++){ print "Thread #2 : $i2\n"; sleep 1;} };
$thr1->join();
$thr2->join();