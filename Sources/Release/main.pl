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
use Net::RTP::Packet;
use Net::SIP;
use Net::SIP::SDP;
use Net::SIP::Packet;
use IO::Socket;
use IO::Select;
use IO::Socket::SSL;
use IO::Interface::Simple;
use threads;
use threads::shared;
use Time::HiRes;
use Getopt::Long;
use Socket;
use POSIX qw(strftime);

my $bgcolor = "black";
my $menucolor = "cyan";
my $fgcolor = "white";
my $windowcolor = "blue";

my $release = "1.0B";
my $license = "SITM version $release, Copyright (C) 2013 IN'TECH INFO
SITM comes with ABSOLUTELY NO WARRANTY
This is a free software.
You can distribute it, under certain conditions.\n
See the file COPYING for details.";

my $cui = new Curses::UI( -color_support => 1,
                          -clear_on_exit => 1,
                          -debug => 1,
                          -bg => $bgcolor);

require 'sys/ioctl.ph';
require "Derma/passwords.pl";
require "Derma/logging.pl";
require "Derma/interface_selection.pl";
require "Derma/target_selection.pl";
require "network_scan.pl";
require "network_listener.pl";
require "Modules/mac_generator.pl";
require "Modules/arp_watcher.pl";
require "Servers/dhcpd.pl";
require "Servers/https.pl";
require "Attacks/arp_query.pl";

my @menu = (
    {
        -label   => 'SITM',
        -submenu => [ { -label => 'Start Sniffing    ^S', -value => sub {InterfacePopup($cui);} }, { -label => 'Stop Sniffing', -value => sub {Stop_NetworkListener();} }, { -label => 'Show Logs         ^L', -value => sub {ShowLogDerma();} }, { -label => 'Credits           ^C', -value => sub {Credits();} }, { -label => 'Exit              ^Q', -value => \&exit_dialog } ]
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
        -submenu => [ { -label => 'ARP Spoofing Attack', -value => sub { ARPQuery_Attack_Start(); } }, ]
    },
    {
        -label   => 'Logs',
        -submenu => [ { -label => 'Passwords', -value => sub { ShowPassDerma(); } }, ]
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
    -fg   => $fgcolor,
    -bg   => GetMenuColor(),
);

CreateLogDerma($cui);
CreatePassDerma($cui);
Init_Bindings($cui);

$cui->set_timer('update_time', \&UpdateLog);

$cui->mainloop();

sub GetMenuColor {
    return $menucolor;
}

sub GetWindowColor {
    return $windowcolor;
}

sub UpdateLog {
    if (GetPipeStatus())
    {
        foreach my $log (GetLog())
        {
            print STDERR $log;
            AddLogEntry($log);
        }
        GoToLast();
        SetPipeStatus();
        ClearPipe();
        #unlink "sitm_pipe.tmp";
        #$DataOnPipe = 0;
    }

    if (GetPassPipeStatus())
    {
        foreach my $log (GetPasswords())
        {
            AddPassEntry($log);
        }
        GoToLastPass();
        SetPassPipeStatus();
        ClearPasswordPipe();
        #unlink "sitm_pipe.tmp";
        #$DataOnPipe = 0;
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
    if ($return){
        system("echo 0 > /proc/sys/net/ipv4/ip_forward");
        foreach my $thr (threads->list()) {
            $thr->exit('KILL') if $thr->can('exit'); 
        }
        goto $cui::DESTROY;
        exit(0);
    }
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
     \\__\\/                                 \\__\\/    \n\n\nStalker In The Middle $release\n\nCreated by the students of IN'TECH INFO : \n\nBUNLON Christie\nCHATELAIN Nicolas\nINQUEL Alban\n\n$license");
}