#!/usr/bin/perl -w

use strict;
use warnings;
use Curses::UI;
use Net::RawIP;
use Net::Pcap::Easy;
use Net::MAC;
use Net::MAC::Vendor;
use Net::ARP;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use Time::HiRes;
use Getopt::Long;
use Socket;
my $VERSION = "1.0 Alpha";
my $debug;
my $cui = new Curses::UI( -color_support => 1,
                          -clear_on_exit => 0,
                          -debug => 1, );

require "Derma/logging.pl";
require "network_scan.pl";
require "bindings.pl";
require "network_listener.pl";
require "Modules/mac_generator.pl";
require "Modules/arp_watcher.pl";

my @menu = (
    {
        -label   => 'SITM',
        -submenu => [ { -label => 'Start Sniffing    ^S', -value => sub {Start_NetworkListener(); DrawNotif("Sniffing demarré !");} }, { -label => 'Exit              ^Q', -value => \&exit_dialog } ]
    },
    {
        -label   => 'Scans',
        -submenu => [ { -label => 'Map Network', -value => sub{MapNetwork($cui,"10.8.97.1","10.8.111.254")} } ]
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
        -submenu => [ { -label => 'Generate Random MAC    ^R', -value => sub { ShowMACGenerated($cui); } }, { -label => 'Set MAC Address        ^M', -value => sub { ShowMACDialog($cui); } }, { -label => 'MITM Protection Module', -value => sub { CheckARPTable($cui); } } ]
    },
);

# Add the Menubar
my $menu = $cui->add(
    'menu', 'Menubar',
    -menu => \@menu,
    -fg   => "white",
    -bg   => "red"
);

CreateLogDerma($cui);
Init_Bindings($cui);

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




