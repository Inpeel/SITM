

sub SendARPProbe {
    Net::ARP::send_packet('wlan0',                 # Device
                '192.168.0.26',          # Source IP
                $_[0],          # Destination IP
                '94:db:c9:47:dc:6d',  # Source MAC
                'FF:FF:FF:FF:FF:FF',  # Destinaton MAC
                'request');             # ARP operation
}

sub GetLocalMac {
     my $if1   = IO::Interface::Simple->new(GetSelectedInterface());
     return $if1->hwaddr;
}

sub Start_NetworkScanner {
    my $currentip; 
    my $i;
    my ($a,$b,$c,$d) = split(/\./, $_[1]);
    my $IPCount = $_[3] - 2; #Don't scan network & broadcast addresses.
    my $msg = "Scan du réseau...\n";
    $_[0]->progress(
        -min => 0,
        -max => $IPCount,
        -title => "Sending ARP Probes",
        -message => $msg,
    );


    do
    {
        $i++;
        $d++;
        $currentip = "$a.$b.$c.$d";
        if ($currentip ne $_[2])
        {
            SendARPProbe($currentip);
        }

        $_[0]->setprogress($i, $msg . $i . " / $IPCount");

        if ($d == 255)
        {
            $c++;
            $d = 0;
        }
        if ($c == 255)
        {
            $b++;
            $c = 0;
        }
        if ($b == 255)
        {
            $a++;
            $b = 0;
        }

    } while ($currentip ne $_[2]);


    $_[0]->setprogress(undef, "Scan terminated - Waiting for ARP Replies...");
    sleep 3;
    $_[0]->noprogress;
    my %hosts = GetResolvedHosts();
    my $count = scalar(keys %hosts);
    AddLogEntry("$count resolved hosts !");
}

return 1;