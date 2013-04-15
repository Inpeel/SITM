#!/usr/bin/perl -w
use Net::Netmask;
my $block = new Net::Netmask ("10.8.96.0", "255.255.240.0");

print "la taille du réseau est:".$block->size()."\n";
print "premiere adresse :".$block->first()."\n";
print "derniere adresse :".$block->last()."\n";

