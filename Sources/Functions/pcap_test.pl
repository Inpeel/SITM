#!/usr/bin/perl -w
use strict;
use warnings;
use Net::Pcap::Easy;
my $SHOW_MAC = 0;
my ($LOCAL_IP,$LOCAL_MASK);
    # all arguments to new are optoinal
    my $npe = Net::Pcap::Easy->new(
        packets_per_loop => 10,
        bytes_to_capture => 1024,
        timeout_in_ms    => 0, # 0ms means forever
        promiscuous      => 0, # true or false

        tcp_callback => sub {
            my ($npe, $ether, $ip, $tcp, $header ) = @_;
            if ($ip->{src_ip} ne "10.8.99.224" and $ip->{dest_ip} ne "10.8.99.224")
            {
                print "[SITM] TCP : $ip->{src_ip}:$tcp->{src_port}"
                 . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";

                print "[ARP INFO] : $ether->{src_mac} -> $ether->{dest_mac}\n" if $SHOW_MAC;
            }
            if ($ip->{dest_ip} eq "10.8.99.224")
            {
                print "[SITM] TCP : $ip->{src_ip}:$tcp->{src_port}"
                 . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";
                print("[FLAG] : $tcp->{flags}\n");
            }
        },

        icmp_callback => sub {
            my ($npe, $ether, $ip, $icmp, $header ) = @_;
            print "[SITM] ICMP: $ether->{src_mac}:$ip->{src_ip}"
             . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
        },

        arp_callback => sub {
            my ($npe, $ether, $arp, $header) = @_;
            if ($arp->{tha} ne "000000000000")
            {
                print("[SITM] ARP : hw addr=$arp->{sha}, " .
                "dest hw addr=$arp->{tha}\n");
            }
        }
    );
	print "Network IP : " .$npe->network ."\n";
	print "Netmask : " .$npe->netmask ."\n";
    1 while $npe->loop;
