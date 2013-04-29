
#!/usr/bin/env perl
use strict;
use warnings;
use 5.010;

use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION = 1;
my $iface="wlan0";

sub mkMACaddress {
    my @values = ();
    push(@values, sprintf("%x0", rand(0xF+1)));

    foreach (2..6) {
        push(@values, sprintf("%02x", rand(0xFF+1)));
    }

    return join(":", @values);
}
my $mac=mkMACaddress;
system("ifconfig wlan0 down");
sleep(1);
system("ifconfig wlan0 hw ether $mac");
sleep(1);
system("ifconfig wlan0 up");
sleep(1);
print "Adresse mac wlan0 modifiée!".$mac;


