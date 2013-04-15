#!/usr/bin/perl -w

use strict;

my $ipdebut = "10.8.96.0"; #Adresse IP de départ
my $ipfin = "10.8.111.255"; # Adresse IP de fin ( Ipdebut => IPfin = range analysé
my $currentip; #IP actuelle lors du scan
my ($a,$b,$c,$d) = split(/\./, $ipdebut); # =(10.8.96.0 => 10.x.x.x)

do # Boucle affichant la liste des adresses IP et parcourant une liste du début à la fin
{
print "$a.$b.$c.$d\n";
$currentip = "$a.$b.$c.$d";
$d++;
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

}while ($currentip ne $ipfin); # on défini la fin du scan lorsque l'IP scanné est égal à l'adresse IP de fin 
