my $im : shared = 0;
my $state : shared = 0;
my $interface;
my $firstip;
my $lastip;
sub SendARPProbe {
    #Envoie une requete ARP afin de resoudre l'adresse MAC.
    Net::ARP::send_packet($interface,                 # Device
                $_[1],          # Source IP
                $_[0],          # Destination IP
                $_[2],  # Source MAC
                'FF:FF:FF:FF:FF:FF',  # Destinaton MAC
                'request');             # ARP operation
}

sub SendTargetTable {
    #Thread permettant d'envoyer les requetes ARPs
    my $ip = get_interface_address(GetSelectedInterface());
    my $mac = get_interface_mac(GetSelectedInterface());
    foreach my $targetip (@_)
    {
        $im++;
        if ($targetip ne $lastip && $targetip ne $firstip)
        {
            SendARPProbe($targetip,$ip,$mac);
        }
    }
    $state++;
    print STDERR "Thread terminated :D !\n";
    return 1;
}

#Obtiens l'adresse MAC de l'interface
sub GetLocalMac {
     my $if1   = IO::Interface::Simple->new(GetSelectedInterface());
     return $if1->hwaddr;
}

#Demarre le scan réseau.
sub Start_NetworkScanner {
    my $currentip; 
    $im = 0;
    $state = 0;
    my $i = 0;
    #Decoupage des adresses
    my ($a,$b,$c,$d) = split(/\./, $_[1]);
    my ($e,$f,$g,$h) = split(/\./, $_[2]);
    #Determination des premieres et dernieres adresses à scanner
    $firstip = $_[1];
    $lastip =  $_[2];
    my $IPCount = $_[3];
    #Nombre de threads à utiliser.
    my $theads_number = $_[4];
    my $iprange = ($IPCount / $theads_number);
    my $msg = "Scan du réseau...\n";
    my @iptoscan = ();
    $_[0]->progress(
        -min => 0,
        -max => $IPCount,
        -title => "Sending ARP Probes (Addresses : $IPCount - Threads : $theads_number)",
        -message => $msg,
    );

    my $ip = get_interface_address(GetSelectedInterface());
    my $mac = get_interface_mac(GetSelectedInterface());
    $interface = GetSelectedInterface();
    do
    {
        if ($d == 256)
        {
            $c++;
            $d = 0;
        }
        if ($c == 256)
        {
            $b++;
            $c = 0;
        }
        if ($b == 256)
        {
            $a++;
            $b = 0;
        }
        $currentip = "$a.$b.$c.$d";
        $d++;
        if ($theads_number == 1)
        {
            $i++;
            #Envoie d'une requete ARP
            SendARPProbe($currentip,$ip,$mac);
            #Affichage des adresses scannés.
            $_[0]->setprogress($i, $msg . $i . " / $IPCount");
        }
        else
        {
            $i++;
            #Lancement des threads.
            push(@iptoscan,$currentip);
            if ($i == $iprange)
            {
                my $t = threads->create({'context' => 'void'},\&SendTargetTable,@iptoscan);
                @iptoscan = ();
                $i = 0;
            }
        }

    } while ($currentip ne $_[2]);
    if ($theads_number > 1)
    {
        while ($state ne $theads_number)
        {
            #Affichage des adresses scannés.
            Time::HiRes::sleep(0.05);
            $_[0]->setprogress($im, $msg . $im . " / $IPCount");
        }
    }
    $_[0]->setprogress($IPCount, $msg . $IPCount . " / $IPCount");
    $_[0]->setprogress(undef, "Scan terminated - Waiting for ARP Replies...");
    #Timer de 4 secondes afin de recevoir les reponses ARP.
    sleep 4;
    $_[0]->noprogress;
    my %hosts = GetResolvedHosts();
    my $count = scalar(keys %hosts);
    AddLogEntry("$count resolved hosts !");
}

return 1;