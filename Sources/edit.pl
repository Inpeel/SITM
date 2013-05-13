#!/usr/bin/perl -w

use strict;
use warnings;
use Curses::UI;
use Net::RawIP;
use Net::Pcap::Easy;
use Net::MAC;
use Net::MAC::Vendor;
use Getopt::Long;
use Socket;
my $VERSION = "1.0 Alpha";

my $cui = new Curses::UI( -color_support => 1 );

# Create a menu
my @menu = (
	{
		-label   => 'SITM',
		-submenu => [ { -label => 'Start Sniffing    ^S', -value => sub {DrawNotif("Sniffing demarré !");} }, { -label => 'Exit              ^Q', -value => \&exit_dialog } ]
	},
	{
		-label   => 'Scans',
		-submenu => [ { -label => 'SYN Scan', -value => sub{MapNetwork("10.8.97.1","10.8.111.254",4096)} }, { -label => 'ARP Scan', -value => \&exit_dialog }, { -label => 'ICMP Scan', -value => \&exit_dialog } ]
	},
	{
		-label   => 'Attaques',
		-submenu => [ { -label => 'ARP Spoofing (REQUEST)', -value => \&exit_dialog }, { -label => 'ARP Spoofing (REPLY)', -value => \&exit_dialog },{ -label => 'DHCP Spoofing (GATEWAY)', -value => \&exit_dialog },{ -label => 'DHCP Spoofing (DNS)', -value => \&exit_dialog },{ -label => 'MAC Address Stealing', -value => \&exit_dialog } ]
	},
    {
        -label   => 'Logs',
        -submenu => [ { -label => 'HTTP Auth', -value => \&exit_dialog }, { -label => 'FTP Auth', -value => \&exit_dialog } ]
    },
    {
        -label   => 'Security',
        -submenu => [ { -label => 'Generate Random MAC    ^R', -value => \&exit_dialog }, { -label => 'Set MAC Address        ^M', -value => \&exit_dialog } ]
    },
);

# Add the Menubar
my $menu = $cui->add(
	'menu', 'Menubar',
	-menu => \@menu,
	-fg   => "white",
	-bg   => "red"
);


# Add a window
my $packetlist = $cui->add(
	'packetlist', 'Window',
	-border => 1,
    -title => "Logs",
	-y      => 15,
	-bfg    => 'red',
);

my $listbox = $packetlist->add(
    'mylistbox', 'Listbox',
    -values    => [1, 2, 3],
    -labels    => { 1 => 'SITM ' .$VERSION. ' Started - '.localtime, 
                    2 => 'Two', 
                    3 => 'Three' }
);


# Making keybindings
$cui->set_binding( sub {DrawNotif("Sniffing demarré !");}, "\cS" );
$cui->set_binding( sub { $menu->focus() }, "\cX" );
$cui->set_binding( \&exit_dialog, "\cQ" );


$cui->mainloop();


# Dialogs
sub exit_dialog {
	my $return = $cui->dialog(
		-message => "Vous êtes sûr ?",
		-title   => "Fermer SITM",
		-buttons => [ 'yes', 'no' ],
	);

	exit(0) if $return;
}

sub DrawNotif {
    $cui->dialog($_[0]);
}

sub SendARPProbe {
    Net::ARP::send_packet('wlan0',                 # Device
                '10.8.99.230',          # Source IP
                $_[1],          # Destination IP
                '94:db:c9:47:dc:6d',  # Source MAC
                'FF:FF:FF:FF:FF:FF',  # Destinaton MAC
                'request');             # ARP operation
}


sub MapNetwork {
    my $currentip; 
    my $i;
    my ($a,$b,$c,$d) = split(/\./, $_[0]);
	my $msg = "Counting from 0 to 4096...\n";
	$cui->progress(
	    -min => 0,
	    -max => 3800,
	    -title => "Sending SYN Probes",
	    -message => $msg,
	);


	do
    {
    	$i++;
        $d++;
        $currentip = "$a.$b.$c.$d";
        SendARPProbe($currentip);

        $cui->setprogress($i, $msg . $i . " / 3800");

        if ($d == 255)
        {
            $c++;
            $d = 0;
        }
        if ($c == 255)
        {
            $b++;
            $c = 0;
        }
        if ($b == 255)
        {
            $a++;
            $b = 0;
        }

    } while ($currentip ne $_[1]);


	$cui->setprogress(undef, "Finished counting!");
	sleep 3;
	$cui->noprogress;



}

