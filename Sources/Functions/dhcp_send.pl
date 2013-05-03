#!/usr/bin/perl -w
use strict;
use warnings;
use Net::DHCP::Packet;
use Net::DHCP::Constants;

my $clientmac = "94dbc947dc6d";
my $clientip = "10.8.108.25";
my $serverip = "10.8.102.6";
my $xid = 0x9F0FD;

sub ForgeDHCPOffer
{
	ForgeDHCPServer(DHCPOFFER());
}

sub ForgeDHCPAck
{
	ForgeDHCPServer(DHCPACK());
}

sub ForgeDHCPServer
{
	my $pac = Net::DHCP::Packet->new(
        'Chaddr' => $clientmac,
        'Xid' => 0x9F0FD,
        'Ciaddr' => $clientip,
        'Siaddr' => $serverip,
        'Hops' => 1);
	$pac->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), $_[0]);
	$pac->addOptionValue(DHO_DHCP_LEASE_TIME(), "3600");
	$pac->addOptionValue(DHO_DHCP_SERVER_IDENTIFIER(), "10.8.124.12");
	$pac->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), "10.0.0.1 10.0.0.2");
	$pac->addOptionValue(DHO_SUBNET_MASK(), "255.255.240.0");
	$pac->addOptionValue(DHO_ROUTERS(), "10.8.97.1");
	$pac->addOptionValue(DHO_DOMAIN_NAME(), "HAXXOR.NET");
	print $pac->toString();
}

ForgeDHCPAck();