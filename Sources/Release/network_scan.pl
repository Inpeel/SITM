
sub SendARPProbe {
    Net::ARP::send_packet('wlan0',                 # Device
                '10.8.99.230',          # Source IP
                $_[0],          # Destination IP
                '94:db:c9:47:dc:6d',  # Source MAC
                'FF:FF:FF:FF:FF:FF',  # Destinaton MAC
                'request');             # ARP operation
}


sub Start_NetworkScanner {
    my $currentip; 
    my $i;
    my ($a,$b,$c,$d) = split(/\./, $_[1]);
    my $msg = "Counting from 0 to 4096...\n";
    $_[0]->progress(
        -min => 0,
        -max => 3800,
        -title => "Sending SYN Probes",
        -message => $msg,
    );


    do
    {
        $i++;
        $d++;
        $currentip = "$a.$b.$c.$d";
        SendARPProbe($currentip);

        $_[0]->setprogress($i, $msg . $i . " / 3800");

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


    $_[0]->setprogress(undef, "Finished counting!");
    sleep 3;
    $_[0]->noprogress;
}

return 1;