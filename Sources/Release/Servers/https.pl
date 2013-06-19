my $ioset = IO::Select->new;
my %socket_map;


sub new_conn {
    my ($host) = @_;
    my $sock = IO::Socket::SSL->new(
        PeerHost => $host,
        PeerPort => "https",
        SSL_verify_mode => SSL_VERIFY_NONE,
    ) or die "failed connect or ssl handshake: $!,$SSL_ERROR";

}

sub new_server {
    my ($host, $port) = @_;
    my $server = IO::Socket::SSL->new(
        LocalAddr => '0.0.0.0',
        LocalPort => 8080,
        ReuseAddr => 1,
        Listen    => 100,
        SSL_cert_file => 'Certs/certificate.pem',
        SSL_key_file => 'Certs/key.pem',
    ) or die "failed to listen: $!";
}

sub new_connection {
    my $server = shift;
    my $client = $server->accept;
    my $client_ip = client_ip($client);
    my $peer = $client->get_servername;

    AddLogInfo("Connection from $client_ip : $peer accepted.\n") if $debug;

    my $remote = new_conn($peer);
    $ioset->add($client);
    $ioset->add($remote);

    $socket_map{$client} = $remote;
    $socket_map{$remote} = $client;
}

sub close_connection {
    my $client = shift;
    my $client_ip = client_ip($client);
    my $remote = $socket_map{$client};
    
    $ioset->remove($client);
    $ioset->remove($remote);

    delete $socket_map{$client};
    delete $socket_map{$remote};

    $client->close;
    $remote->close;

    AddLogInfo("Connection from $client_ip closed.\n") if $debug;
}

sub client_ip {
    my $client = shift;
    if ($client && $client->sockaddr)
    {
        return inet_ntoa($client->sockaddr);
    }
    return "Unknown"
}

sub Start_HTTP_SSL_Server_Thread {
	AddLogInfo("Starting SITM HTTPS Server on 0.0.0.0:8080\n");
	open(FDD,">>log");
	my $server = new_server();
	$ioset->add($server);

	while (1) {
	    for my $socket ($ioset->can_read) {
	        if ($socket == $server) {
	            fork();fork();fork();fork();
	            new_connection($server);
	        }
	        else {
	            next unless exists $socket_map{$socket};
	            my $remote = $socket_map{$socket};
	            my $buffer;
	            my $read = $socket->sysread($buffer, 4096);
	            if ($read) {

                	foreach my $data (split(/\n/, $buffer))
                	{
                		AddLogInfo($data."\r\n");
                	}
	                print FDD $buffer;
	                $remote->syswrite($buffer);
	            }
	            else {
	                close_connection($socket);
	            }
	        }
	    }
	}
	close FDD;
}

return 1;