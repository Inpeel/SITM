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

my $SHOW_MAC = 0;

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
		-submenu => [ { -label => 'ARP Spoofing', -value => \&exit_dialog }, { -label => 'DHCP Spoofing', -value => \&exit_dialog } ]
	},
    {
        -label   => 'Logs',
        -submenu => [ { -label => 'HTTP Auth', -value => \&exit_dialog }, { -label => 'FTP Auth', -value => \&exit_dialog } ]
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
my $win1 = $cui->add(
	'win1', 'Window',
	-border => 1,
    -title => "Packets",
	-y      => 15,
	-bfg    => 'red',
);

my $listbox = $win1->add(
    'mylistbox', 'Listbox',
    -values    => [1, 2, 3],
    -labels    => { 1 => 'One', 
                    2 => 'Two', 
                    3 => 'Three' },
    -radio     => 1,
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

sub PrintSomeShit {
	print("HELLO WORLD !");
}


sub StartCap
{
    my $npe = Net::Pcap::Easy->new(
        packets_per_loop => 10,
        bytes_to_capture => 1024,
        timeout_in_ms    => 0, # 0ms means forever
        promiscuous      => 0, # true or false

        tcp_callback => sub {
            my ($npe, $ether, $ip, $tcp, $header ) = @_;
            if ($ip->{src_ip} ne "10.8.99.230" and $ip->{dest_ip} ne "10.8.99.230")
            {
                print "[SITM] TCP : $ip->{src_ip}:$tcp->{src_port}"
                 . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";
                print "[TCP INFO] : $ether->{src_mac} -> $ether->{dest_mac}\n" if $SHOW_MAC;

    	
            }
            if ($ip->{dest_ip} eq "10.8.99.230x" )
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
    MapNetwork($block->first(),$block->last());
    1 while $npe->loop;
}

sub DrawNotif {
    $cui->dialog($_[0]);
    sleep 3;
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

sub SendSYNProbe {
	my $n = Net::RawIP->new({
                        ip  => {
                                saddr => '10.8.99.230',
                                daddr => $_[0],
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
        SendSYNProbe($currentip);

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

