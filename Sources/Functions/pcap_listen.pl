#!/usr/bin/perl -w
use strict;
use warnings;
use Net::RawIP;
use Net::Pcap::Easy;
use Net::MAC;
use Net::MAC::Vendor;
use Socket;
my $SHOW_MAC = 0;
my ($LOCAL_IP,$LOCAL_MASK);

sub StartCap()
{
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
                print "[TCP INFO] : $ether->{src_mac} -> $ether->{dest_mac}\n" if $SHOW_MAC;

    	
            }
            if ($ip->{dest_ip} eq "10.8.99.224x" )
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
		my $ipsrc = join ".", map { hex }($arp->{spa} =~ /([[:xdigit:]]{2})/g);
		my $macsrc = join ":", ($arp->{sha} =~ /([[:xdigit:]]{2})/g);
		my $hostname = ResolveHostName($ipsrc);
                print("[SITM] ARP Reply : hw addr=$macsrc [ ".LookupMacVendor($macsrc)." ], " .
                "resolved IP Address : $ipsrc [ ".$hostname." ]\n");
            }
        }
    );
    print "Network IP : " .$npe->network ."\n";
    print "Netmask : " .$npe->netmask ."\n";
    my $block = GetLocalNetInfo($npe->network, $npe->netmask);

    print "la taille du réseau est:".$block->size()."\n";
    print "premiere adresse :".$block->first()."\n";
    print "derniere adresse :".$block->last()."\n";
    1 while $npe->loop;
}

sub ResolveHostName {
    my $hostname = gethostbyaddr(inet_aton($_[0]), AF_INET);
    if ($hostname)
    {
	return $hostname;
    }
    else
    {
	return "Unknown";
    }
}

sub LookupMacVendor {
    my $cmac = Net::MAC->new('mac' => $_[0])->convert(
            'base' => 16,
            'bit_group' => 8,
            'delimiter' => ':'
    ); 
    my $vendor = Net::MAC::Vendor::lookup( $cmac );;
    if (@$vendor[0])
    {
        return @$vendor[0];
    }
    else
    {
        return "Unknown"
    }
}

sub GetLocalNetInfo {
    my $block = new Net::Netmask($_[0],$_[1]);
    return $block;
}

sub MapNetwork {
    my $currentip; 
    my ($a,$b,$c,$d) = split(/\./, $_[0]);

    do
    {
        $d++;
        $currentip = "$a.$b.$c.$d";
        print "Probing : $a.$b.$c.$d\n";
        my $n = Net::RawIP->new({
                        ip  => {
                                saddr => '10.8.99.224',
                                daddr => $currentip,
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
        if ($d == 255)
        {
            $c++;
            $d = 0;
        }
        if ($c == 255)
        {
            $b++;
            $c =0;
        }
        if ($b == 255)
        {
            $a++;
            $b = 0;
        }

    } while ($currentip ne $_[1]);

}


StartCap();
