#!/usr/bin/perl -w
use strict;
use warnings;
use Net::Pcap;
my %devinfo;
my $err;
my @devs = pcap_findalldevs(\%devinfo, \$err);
for my $dev (@devs) {
    print "$dev : $devinfo{$dev}\n"
}