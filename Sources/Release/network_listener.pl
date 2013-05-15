my $DataOnPipe : shared = 0;
my %ResolvedHosts : shared = ();

sub Start_NetworkListener{
    my $NetworkListener = threads->new(\&Start_NetworkListener_Thread);
    $NetworkListener->detach();
}

sub AddDataToPipe{
    open (FH,">sitm_pipe.tmp") or die print STDERR "FILE ERROR !";
    print FH $_[0];
    close FH;
    $DataOnPipe = 1;
}

sub GetPipeStatus{
    return $DataOnPipe;
}

sub SetPipeStatus{
    $DataOnPipe = 0;
}

sub AddResolvedHost{
    $ResolvedHosts{$_[0]} = $_[1];
}

sub GetResolvedHosts{
    return %ResolvedHosts;
}

sub Start_NetworkListener_Thread
{
        my $npe = Net::Pcap::Easy->new(
            dev              => "wlan0",
            timeout_in_ms    => 0, # 0ms means forever
            promiscuous      => 1, # true or false

            tcp_callback => sub {
                my ($npe, $ether, $ip, $tcp, $header ) = @_;
                if ($ip->{src_ip} ne "10.8.99.230" and $ip->{dest_ip} ne "10.8.99.230")
                {
                    AddDataToPipe("TCP : $ip->{src_ip}:$tcp->{src_port}"
                     . " -> $ip->{dest_ip}:$tcp->{dest_port}\n");
                    AddDataToPipe("[TCP INFO] : $ether->{src_mac} -> $ether->{dest_mac}\n") if $SHOW_MAC;

        	
                }
                if ($ip->{dest_ip} eq "10.8.99.230x" )
                {
                    AddDataToPipe("TCP : $ip->{src_ip}:$tcp->{src_port}"
                     . " -> $ip->{dest_ip}:$tcp->{dest_port}\n");
                    AddDataToPipe("[FLAG] : $tcp->{flags}\n");
                }
                #if ($tcp->{dest_port} == 80 || $tcp->{src_port} == 80){
                #    AddDataToPipe "[SITM] Got HTTP Request !\n";
                #        AddDataToPipe $tcp->{data};
                #}

            },

            icmp_callback => sub {
                my ($npe, $ether, $ip, $icmp, $header ) = @_;
                AddDataToPipe("ICMP: $ether->{src_mac}:$ip->{src_ip}"
                 . " -> $ether->{dest_mac}:$ip->{dest_ip}\n");
            },

            udp_callback => sub {
                my ($npe, $ether, $ip, $udp, $header ) = @_;
                if ($udp->{dest_port} == 67)
                {
                    AddDataToPipe("Got DHCP Request from $ether->{src_mac}!\n");
                    my $packet = Net::DHCP::Packet->new($udp->{data});
                    AddDataToPipe("DHCP Message Type : ".$packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE())."\n");
                    if ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 1)
                    {
                        AddDataToPipe("Got DHCP Discover !\n");
                        #ForgeDHCPServer($packet->xid(),"192.168.0.2","192.168.0.1",DHCPOFFER(),$ether->{src_mac});
                    }
                    elsif ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 3)
                    {
                        AddDataToPipe("Got DHCP Request !\n");
                        #ForgeDHCPServer($packet->xid(),"192.168.0.2","192.168.0.1",DHCPACK(),$ether->{src_mac});
                    }
                }
            },

            arp_callback => sub {
                my ($npe, $ether, $arp, $header) = @_;
                if ($arp->{opcode} == 2)
                {
            		my $ipsrc = IPFormat($arp->{spa});
            		my $macsrc = MacFormat($arp->{sha});
            		my $hostname = ResolveHostName($ipsrc);
                    AddDataToPipe("ARP Reply : hw addr=$macsrc [ ".LookupMacVendor($macsrc)." ], " .
                    "resolved IP Address : $ipsrc [ ".$hostname." ]\n");
                    AddResolvedHost($ipsrc,$macsrc);
                }
                
            }
        );
        AddDataToPipe("Network IP : " .$npe->network ."\n");
        AddDataToPipe("Netmask : " .$npe->netmask ."\n");

        my $block = GetLocalNetInfo($npe->network, $npe->netmask);
        AddDataToPipe("SITM Network Listener [".$block->first()."][".$block->last()."] started.");

        1 while $npe->loop;
    
}

sub GetLocalNetInfo {
    my $block = new Net::Netmask($_[0],$_[1]);
    return $block;
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


return 1;