#!/usr/bin/perl
#  Simple HTTP Proxy Program using HTTP::Daemon.
#  (c) 2007 by Takaki Makino  http://www.snowelm.com/~t/

use strict;
use warnings;
use URI::Find;
use URI::Escape;
use HTTP::Daemon;
use LWP::UserAgent;
my $tmp;
my @cache;

my $ua = LWP::UserAgent->new(keep_alive => 5);
my $http = HTTP::Daemon->new( 
	LocalPort => 80, 
	reuse => 1
) || die;
print "[Proxy URL:", $http->url, "]\n";


# Avoid dying from browser cancel
#$SIG{PIPE} = 'IGNORE';


print "En attente d'un client..\n";
# Dirty pre-fork implementation
fork(); fork(); fork();fork();fork(); fork(); fork();fork();# 2^3 = 8 processes

while (my $c = $http->accept) {
	print "Requête d'un nouveau client..\n"; 

        while (my $request = $c->get_request) {
        	#print("Request Host : ".$request->header("Host") . "\n"); 
        	#print("Request URI : ".$request->uri . "\n");
        	#print("Modified URI : http://".$request->header("Host").$request->uri."\n");
        	$request->uri("http://".$request->header("Host").$request->uri);
			#print "LIEN REQUETE : ".$request->uri."\n";
			
			#if(@cache){
				#print "RIEN DANS LE CASH\n";
			#}
			#foreach my $ptr (@cache){
			#	print "LIEN CACHE : $ptr\n";
			#	open (TAB, ">>tab.txt");
			#	print TAB "requete a envoyé : ".$request->uri."\n";
			#	print TAB "requete en cache : ".$ptr."\n";
			#	close TAB;
			#	if($ptr eq $request->uri){
					#print "Lien Similaire trouvé\n";
					#$request->uri =~ s/^://;
					#print "LIEN REQUETE MODIFIE : ".$request->uri."\n";
					
			#	}
			#}
			
			RESEND:
			print "Envoi requete\n";
			my $response = $ua->request( $request );
			if($response){
				print "Réponse du serveur\n";
			}
			#print $response->content;

			print "LE STATUT DE LA REQUETE EST : ".$response->status_line."\n";
			#if($response->status_line eq "301 Found"){
			#	print "Checking new location...\n";
			#	if($response->header("Location") =~ /((([A-Za-z]{3,9}:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/){
			#		$response->header("Location") =~ s/https/http/;
			#		$request->uri($response->header("Location").$request->uri);
			#		print "Renvoi de la requete : 301\n";
			#		goto RESEND;
			#	}
			#}
			

			#if ($response->content =~ m/https:\/\//){
				#print "https trouvé!!\n\n\n\n\n";
				
				if(my $content_encoding = $response->header("Content-Encoding")){
					print "La methode d encodage est  :  $content_encoding\n\n\n\n";
					$tmp = $response->decoded_content($content_encoding);
				}else{
					$tmp = $response->decoded_content("UTF-8");
				}
				open (SOURCE, ">>source.html");
				print SOURCE $tmp;
				close SOURCE;
				#$tmp = $response->decoded_content;
				
				
				open (MODIFIED, ">>modified.html");
				if($tmp =~ /((([A-Za-z]{3,9}:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/g){
					print MODIFIED "$&\n";
					$tmp =~ s/https/http/g;
				}
			
				close MODIFIED;
				#foreach my $i (@cache){
				#	if($i =~ m/^https.*$/){
				#		$i =~ s/https/http/g;
						#print MODIFIED "URL HTTPS MODIFIE\n";
						#print MODIFIED "$i\n\n";
				#	}else{
						#print MODIFIED "$i\n";
				#	}
					
				#}
				
			
				#open (MODIFIED, ">>tab.txt");
				#print MODIFIED  $tmp;
				#close MODIFIED;
				#$c->send_response($tmp);
		
			
			#$c->send_basic_header( $response->status_line );
			#$c->send_file_response( "modified.html" );
			#$c->send_status_line( "200" );
			#$c->send_header("Content-Type",$response->header("Content-Type"));
			#$c->send_header("Content-Length",length($tmp));
			#$c->send_crlf();
			#$c->send_response("RESP HIERE");
				#if($response->header("Connection")){
				#	print "serveur : ".$response->header("Connection")."\n";
				#}
				#if(!$response->status_line){
				#	$response->status_line = "200 OK";
				#}
			if($c->send_response($response->status_line."\r\nServer: KIKOULOL/0.0\r\nContent-Type : ".$response->header("Content-Type") ."\r\nContent-Length: ".length($tmp)."\r\nConnection: ".$response->header("Connection")."\r\n\r\n".$tmp)){
				print "Réponse envoyée au client\n";
			}else{
				print "\nRéponse non envoyé au client\nNouvelle tentative...\n";
			}
		}
		print "Fin d'envoi au client.\n\n";
		$c->close;
		undef($c);	
		
		print "En attente d'une requête\n";
}


