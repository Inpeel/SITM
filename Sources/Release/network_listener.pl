my $DataOnPipe : shared = 0;
my %ResolvedHosts : shared = ();
my @LogEntry : shared = ();
my $Sniffer_Started = 0;
my $NetworkListener;

sub Start_NetworkListener{

    my $NetworkListener = threads->new(\&Start_NetworkListener_Thread);
    $NetworkListener->detach();
    $Sniffer_Started = 1;
}

sub GetSnifferStatus{
    return $Sniffer_Started;
}

sub Stop_NetworkListener{
    if ($NetworkListener){
        $NetworkListener->kill() if $NetworkListener->can('exit'); 
        $Sniffer_Started = 0;
    }
}

sub AddLogInfo{
    push(@LogEntry, $_[0]);
    $DataOnPipe = 1;
}

sub GetLog{
    return @LogEntry;
}

sub GetPipeStatus{
    return $DataOnPipe;
}

sub SetPipeStatus{
    $DataOnPipe = 0;
}

sub ClearPipe{
    @LogEntry = ();
}

sub AddResolvedHost{
    $ResolvedHosts{$_[0]} = $_[1];
}

sub GetResolvedHosts{
    return %ResolvedHosts;
}

sub Start_NetworkListener_Thread
{
        my $ipaddress = get_interface_address(GetSelectedInterface());
        my $npe = Net::Pcap::Easy->new(
            dev              => GetSelectedInterface(),
            timeout_in_ms    => 0,
            promiscuous      => 1,

            tcp_callback => sub {
                my ($npe, $ether, $ip, $tcp, $header ) = @_;
                if ($ip->{src_ip} ne $ipaddress and $ip->{dest_ip} ne $ipaddress)
                {
                    AddLogInfo("TCP : $ip->{src_ip}:$tcp->{src_port}"
                     . " -> $ip->{dest_ip}:$tcp->{dest_port}\n");
                    AddLogInfo("[TCP INFO] : $ether->{src_mac} -> $ether->{dest_mac}\n") if $SHOW_MAC;

        	
                }
            },

            udp_callback => sub {
                my ($npe, $ether, $ip, $udp, $header ) = @_;
                if ($udp->{dest_port} == 67)
                {
                    AddLogInfo("Got DHCP Request from $ether->{src_mac}!\n");
                    my $packet = Net::DHCP::Packet->new($udp->{data});
                    AddLogInfo("DHCP Message Type : ".$packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE())."\n");
                    if ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 1)
                    {
                        AddLogInfo("Got DHCP Discover !\n");
                        #ForgeDHCPServer($packet->xid(),"192.168.0.2","192.168.0.1",DHCPOFFER(),$ether->{src_mac});
                    }
                    elsif ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 3)
                    {
                        AddLogInfo("Got DHCP Request !\n");
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
                    AddLogInfo("ARP Reply : hw addr=$macsrc [ ".LookupMacVendor($macsrc)." ], " .
                    "resolved IP Address : $ipsrc [ ".$hostname." ]\n");
                    AddResolvedHost($ipsrc,$macsrc);
                }
                
            }
        );
        AddLogInfo("Network IP : " .$npe->network ."\n");
        AddLogInfo("Netmask : " .$npe->netmask ."\n");

        my $block = GetLocalNetInfo($npe->network, $npe->netmask);
        AddLogInfo("SITM Network Listener [".$block->first()."][".$block->last()."] started.");

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

sub get_interface_address
{
    my ($iface) = @_;
    my $socket;
    socket($socket, PF_INET, SOCK_STREAM, (getprotobyname('tcp'))[2]) || die "unable to create a socket: $!\n";
    my $buf = pack('a256', $iface);
    if (ioctl($socket, SIOCGIFADDR(), $buf) && (my @address = unpack('x20 C4', $buf)))
    {
        return join('.', @address);
    }
    return undef;
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