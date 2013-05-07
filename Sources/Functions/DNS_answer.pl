#!/usr/bin/perl
 
use strict;
use warnings;
use Net::DNS::Nameserver;
  
sub reply_handler {
	my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	my ($rcode, @ans, @auth, @add);
           
	print "Received query from $peerhost to ". $conn->{sockhost}. "\n";

	if ($qtype eq "A") {
		my ($ttl, $rdata) = (3600, "192.168.0.2");
		my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
		push @ans, $rr;
		$rcode = "NOERROR";

	}elsif( $qname eq "www.google.com" ) {

		$rcode = "NOERROR";

	}else{
		$rcode = "NXDOMAIN";
	}                                                                                                            
	# mark the answer as authoritive (by setting the 'aa' flag
	return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}

my $ns = new Net::DNS::Nameserver(
	LocalPort    => 53,
	ReplyHandler => \&reply_handler,
	Verbose	     => 1
) || die "couldn't create nameserver object\n";

$ns->main_loop;
