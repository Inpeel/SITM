#!/usr/bin/perl -w

use strict;
use warnings;
use Curses::UI;
use Net::RawIP;
use Net::Pcap;
use Net::Pcap::Easy;
use Net::MAC;
use Net::MAC::Vendor;
use Net::ARP;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use threads;
use threads::shared;
use Time::HiRes;
use Getopt::Long;
use Socket;
my $release = "1.0B";
my $license = "SITM version $release, Copyright (C) 2013 IN'TECH INFO
SITM comes with ABSOLUTELY NO WARRANTY
This is a free software.
You can distribute it, under certain conditions.\n
See the file COPYING for details.";

my $cui = new Curses::UI( -color_support => 1,
                          -clear_on_exit => 0,
                          -debug => 1, );

require 'sys/ioctl.ph';
require "Derma/logging.pl";
require "Derma/interface_selection.pl";
require "Derma/target_selection.pl";
require "network_scan.pl";
require "network_listener.pl";
require "Modules/mac_generator.pl";
require "Modules/arp_watcher.pl";

my @menu = (
    {
        -label   => 'SITM',
        -submenu => [ { -label => 'Start Sniffing    ^S', -value => sub {InterfacePopup($cui);} }, { -label => 'Show Logs         ^L', -value => sub {ShowLogDerma();} }, { -label => 'Credits           ^C', -value => sub {Credits();} }, { -label => 'Exit              ^Q', -value => \&exit_dialog } ]
    },
    {
        -label   => 'Scans',
        -submenu => [ 
            { -label => 'Map Network', -value => sub{ 
                    if (GetSnifferStatus()) { 
                        my ($network,$mask,$size) = GetSelectedInterfaceNetwork();
                        Start_NetworkScanner($cui,$network,$mask,$size); 
                    } 
                    else 
                    { 
                        DrawNotif("Sniffer must be started first !\n");
                    }
                }
            },
            { -label => 'Get Resolved Hosts', -value => sub{ ShowTargets($cui); } } ]
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

$cui->set_timer('update_time', \&UpdateLog);

$cui->mainloop();

sub UpdateLog {
    if (GetPipeStatus())
    {
        print STDERR "PIPE REPONSE !\n";
        #Lire le PIPE !

        foreach my $log (GetLog())
        {
            print STDERR $log;
            AddLogEntry($log);
        }
       
        SetPipeStatus();
        ClearPipe();
        #unlink "sitm_pipe.tmp";
        #$DataOnPipe = 0;
    }
    else
    {
        print STDERR "No pipe\n";
    }
}

sub GetHosts{
    my %hosts = GetResolvedHosts();
    foreach my $k (keys(%hosts)) {
       AddLogEntry("IP=$k MAC=$hosts{$k}\n");
    }
}

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

sub Init_Bindings{
    $cui->set_binding( sub {InterfacePopup($cui);}, "\cS" );
    $cui->set_binding( sub { $menu->focus() }, "\cX" );
    $cui->set_binding( sub { ShowTargets($cui); }, "\cH" );
    $cui->set_binding( sub { if (GetSnifferStatus()) { 
                        my ($network,$mask,$size) = GetSelectedInterfaceNetwork();
                        Start_NetworkScanner($cui,$network,$mask,$size); 
                    } 
                    else 
                    { 
                        DrawNotif("Sniffer must be started first !\n");
                    } }, "\cM" );
    $cui->set_binding( \&exit_dialog, "\cQ" );
}


sub Credits{
    DrawNotif("
      ___                                   ___     
     /  /\\        ___           ___        /__/\\    
    /  /:/_      /  /\\         /  /\\      |  |::\\   
   /  /:/ /\\    /  /:/        /  /:/      |  |:|:\\  
  /  /:/ /::\\  /__/::\\       /  /:/     __|__|:|\\:\\ 
 /__/:/ /:/\\:\\ \\__\\/\\:\\__   /  /::\\    /__/::::| \\:\\
 \\  \\:\\/:/~/:/    \\  \\:\\/\\ /__/:/\\:\\   \\  \\:\\~~\\__\\/
  \\  \\::/ /:/      \\__\\::/ \\__\\/  \\:\\   \\  \\:\\      
   \\__\\/ /:/       /__/:/       \\  \\:\\   \\  \\:\\     
     /__/:/        \\__\\/         \\__\\/    \\  \\:\\    
     \\__\\/                                 \\__\\/    \n\n\nStalker In The Middle $release\n\nCreated by the students of IN'TECH INFO : \n\nBUNLON Christie\nCHATELAIN Nicolas\nHOFFMANN Brice\nINQUEL Alban\n\n$license");
}