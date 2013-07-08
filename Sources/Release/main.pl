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
use Net::DNS::Nameserver;
use WWW::Mechanize::Firefox;
use MIME::Base64;
use URI::Escape;
 use threads ('yield',
'stack_size' => 64*4096,
'exit' => 'threads_only',
'stringify');
use threads::shared;
use Time::HiRes;
use Getopt::Long;
use Encode;
use HTTP::Daemon;
use LWP::UserAgent;
use Crypt::SSLeay;
use LWP::Protocol::https;
use Socket;
use POSIX qw(strftime);
use Encode qw/decode/;

my $bgcolor = "black";
my $menucolor = "magenta";
my $fgcolor = "white";
my $windowcolor = "blue";

my $release = "1.0B";
my $license = "SITM version $release, Copyright (C) 2013 IN'TECH INFO
SITM comes with ABSOLUTELY NO WARRANTY
This is a free software.
You can distribute it, under certain conditions.\n
See the file COPYING for details.";

#Initialisation de la GUI
my $cui = new Curses::UI( -color_support => 1,
                          -clear_on_exit => 1,
                          -debug => 1,
                          -bg => $bgcolor);

#Chargement des dependances necessaires
require 'sys/ioctl.ph';
require "Derma/passwords.pl";
require "Derma/logging.pl";
require "Derma/interface_selection.pl";
require "Derma/target_selection.pl";
require "Derma/sessions.pl";
require "network_scan.pl";
require "network_listener.pl";
require "Modules/mac_generator.pl";
require "Modules/arp_watcher.pl";
require "Servers/dhcpd.pl";
require "Servers/https.pl";
require "Servers/dns.pl";
require "Servers/http_striping.pl";
require "Attacks/arp_query.pl";

#Liste des themes
my $theme_menu = [
        { -label => 'RedFish', -value => sub { ChangeTheme("red"); } },
        { -label => 'BlueLagoon', -value => sub { ChangeTheme("blue"); } },
        { -label => 'WinterNight', -value => sub { ChangeTheme("magenta"); } },
        { -label => 'Lemoncello', -value => sub { ChangeTheme("yellow"); } },
        { -label => 'Flatgrass', -value => sub { ChangeTheme("green"); } },
        { -label => 'SkyTheme', -value => sub { ChangeTheme("cyan"); } },
    ];

#Liste des themes
my $promisscan_menu = [
        { -label => 'B31 Scan', -value => sub { if (GetSnifferStatus()) { PromisScannerComputeHosts($cui,"B31"); } else { DrawNotif("Sniffer must be started first"); } } },
        { -label => 'B16 Scan', -value => sub { if (GetSnifferStatus()) { PromisScannerComputeHosts($cui,"B16"); } else { DrawNotif("Sniffer must be started first"); } } },
        { -label => 'B8 Scan', -value => sub { if (GetSnifferStatus()) { PromisScannerComputeHosts($cui,"B8"); } else { DrawNotif("Sniffer must be started first"); } } },
        { -label => 'Complete Scan', -value => sub { if (GetSnifferStatus()) { PromisScannerComputeHosts($cui,"COMPLETE"); } else { DrawNotif("Sniffer must be started first"); } } },,
    ];

#Elements du menu
my @menu = (
    {
        -label   => 'SITM',
        -submenu => [ { -label => 'Start Sniffing    ^S', 
            -value => sub {
                if (GetSnifferStatus()) { 
                    DrawNotif("Sniffer already started...");
                }
                else
                {
                    InterfacePopup($cui);
                }
                
            } 
        }, { -label => 'Stop Sniffing', -value => sub {Stop_NetworkListener(); ARPQuery_Attack_Stop();} }, { -label => 'Show Logs         ^L', -value => sub {ShowLogDerma();} }, { -label => 'Credits           ^C', -value => sub {Credits();} },  { -label => 'Themes', -submenu => $theme_menu, },  { -label => 'Exit              ^Q', -value => \&exit_dialog } ]
    },
    {
        -label   => 'Scans',
        -submenu => [ 
            { -label => 'Passive Network Mapping', -value => sub{ 
                    if (GetSnifferStatus()) { 
                        my ($network,$mask,$size) = GetSelectedInterfaceNetwork();
                        Start_NetworkScanner($cui,$network,$mask,$size,1); 
                    } 
                    else 
                    { 
                        DrawNotif("Sniffer must be started first.");
                    }
                }
            },
            { -label => 'Fast Network Mapping', -value => sub{ 
                    if (GetSnifferStatus()) { 
                        my ($network,$mask,$size) = GetSelectedInterfaceNetwork();
                        Start_NetworkScanner($cui,$network,$mask,$size,2); 
                    } 
                    else 
                    { 
                        DrawNotif("Sniffer must be started first.");
                    }
                }
            },
            { -label => 'Aggressive Network Mapping', -value => sub{ 
                    if (GetSnifferStatus()) { 
                        my ($network,$mask,$size) = GetSelectedInterfaceNetwork();
                        Start_NetworkScanner($cui,$network,$mask,$size,4); 
                    } 
                    else 
                    { 
                        DrawNotif("Sniffer must be started first.");
                    }
                }
            },
             ]
    },
    {
        -label   => 'Attacks',
        -submenu => [ 
            { -label => 'Setup Attack', -value => sub{ ShowTargets($cui); } },  
            { -label => 'ARP Spoofing Attack', 
                -value => 
                sub {
                    if (GetSnifferStatus()) {  
                        my %targets = GetAttackTargets();
                        my @Settings = GetSettings();
                        if (scalar(keys %targets) > 0)
                        {
                            if (3 ~~ @Settings)
                            {
                                 my $value = $cui->dialog(
                                   -message => "WARNING ! NTLM USE TWO WAY ARP POISONING ! Attack may be logged. Continue ?",
                                       -buttons => ['yes', 'no'],
                                       -title   => 'SITM WARNING',
                                );
                                if ($value){
                                    ARPQuery_Attack_Start();
                                }
                            }
                           else
                           {
                            ARPQuery_Attack_Start();
                           }
                            
                        }
                        else
                        {
                            DrawNotif("No targets selected.")
                        }
                    }
                    else
                    {
                        DrawNotif("Sniffer must be started first.");
                    }
                     
                } 
            }, 
            { -label => 'Two-Way ARP Spoofing Attack', 
                -value => 
                sub {
                    if (GetSnifferStatus()) {  
                        my %targets = GetAttackTargets();
                        my @Settings = GetSettings();
                        if (scalar(keys %targets) > 0)
                        {
                                 my $value = $cui->dialog(
                                   -message => "WARNING ! Using Two-Way ARP Poisoning is not very stealth. Continue ?",
                                       -buttons => ['yes', 'no'],
                                       -title   => 'SITM WARNING',
                                );
                                if ($value){
                                    ARPQuery_Attack_Start(1);
                                }
                        }
                        else
                        {
                            DrawNotif("No targets selected.")
                        }
                    }
                    else
                    {
                        DrawNotif("Sniffer must be started first.");
                    }
                     
                } 
            }, 


        ]
    },
    {
        -label   => 'Logs',
        -submenu => [ { -label => 'Passwords', -value => sub { ShowPassDerma(); } }, { -label => 'Sessions', -value => sub { ShowSessionDerma(); } }, ]
    },
    {
        -label   => 'Security',
        -submenu => [ { -label => 'Generate Random MAC    ^R', -value => sub { ShowMACGenerated($cui); } }, { -label => 'Set MAC Address        ^M', -value => sub { ShowMACDialog($cui); } }, { -label => 'DHCP Renew', -value => sub { RestartDHCP(); } }, { -label => 'MITM Protection Module', -value => sub { CheckARPTable($cui); } },

        { -label => 'Promiscuous Scanner', -submenu => $promisscan_menu,
            },
             ]
    },
);

#Creation du menu
my $menu = $cui->add(
    'menu', 'Menubar',
    -menu => \@menu,
    -fg   => $fgcolor,
    -bg   => GetMenuColor(),
);

#Permet de changer de theme
sub ChangeTheme {
    $menu->set_color_bg($_[0]);
    $windowcolor = $_[0];
}


#Creation des elements du GUI
CreateLogDerma($cui);
CreatePassDerma($cui);
CreateSessionDerma($cui);

#Chargement des raccourcis
Init_Bindings($cui);

#Timer mettant à jour les logs
$cui->set_timer('update_time', \&UpdateLog);

#Boucle sur la GUI
$cui->mainloop();

#Utilisé pour obtenir les informations sur la couleur des elements
sub GetMenuColor {
    return $menucolor;
}

sub GetWindowColor {
    return $windowcolor;
}

#Lecture du "pipe" inter-thread et ajout dans la GUI
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

#Affiche la liste des hotes
sub GetHosts{
    my %hosts = GetResolvedHosts();
    foreach my $k (keys(%hosts)) {
       AddLogEntry("IP=$k MAC=$hosts{$k}\n");
    }
}

#Dialogue de fermeture 
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
        exit(0);
    }
}

#Affiche un message de notification
sub DrawNotif {
    $cui->dialog($_[0]);
}


#Raccourcis
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

#Affiche les credits
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