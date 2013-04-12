#!/usr/bin/perl -w
use Net::RawIP;
my $n = Net::RawIP->new({
                    ip  => {
                            saddr => '10.8.99.224',
                            daddr => '10.8.97.1',
                           },
                  },
                  tcp => {
                            source => 31337,
                            dest   => 54321,
                            psh    => 1,
                            syn    => 0,
                          });;
$n->send;
$n->ethnew("wlan0");
