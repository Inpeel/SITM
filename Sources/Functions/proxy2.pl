#!/usr/bin/perl
#  Simple HTTP Proxy Program using HTTP::Daemon.#  (c) 2007 by Takaki Makino  http://www.snowelm.com/~t/

use strict;
use warnings;

use URI::Find;
use URI::Escape;
use HTTP::Daemon;
use LWP::UserAgent;
use Crypt::SSLeay;
use LWP::Protocol::https;
my $tmp, @cache_cookie=();
my @cache;
my $pa = LWP::UserAgent->new;
my $ua = LWP::UserAgent->new(keep_alive => 5, requests_redirectable => []);
my $http = HTTP::Daemon->new( 
	LocalPort => 80, 
	reuse => 1
) || die;
print "[Proxy URL:", $http->url, "]\n";
#BEGIN {
	#$Net::HTTPS::SSL_SOCKET_CLASS = "Net::SSL";
	#$ENV{HTTPS_PROXY} = '192.168.228.156:80';
#}
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
			
			
			RESEND:
			print "Envoi requete\n";
			@{ $ua->requests_redirectable } = ();
			my $response = $ua->request( $request );
			if($response){
				print "Réponse du serveur\n";
			}
			
			CHECK_CODE:
			print "LE STATUT DE LA REQUETE EST : ".$response->status_line."\n";
			print "Code de la requete :".$response->code."\n";
			
			if($response->code == 301){
				print "Checking new location...\n";
				
				$request->uri("");
				$request->uri($response->header("Location").$request->uri);
				#if($response = $ua->get("https://www.google.fr")){
				#}else{
				#	die "bleme de connexion https\n";
				#}
 				#$response = $ua->get("http://www.orange.fr");
 				#print "Reponse http apres code 301 : ".$response->decoded_content."\n";
				#open (MODIFIED, ">>tab.txt");
				#print MODIFIED "Reponse http apres code 301\n\n";
				#print MODIFIED $response->decoded_content."\n";
				#close MODIFIED;
				print "Renvoi de la requete : 301\n";
				print "URL envoyé : ".$request->uri."\n";
				push
				if($response = $ua->request( $request )){
					print "Requete 301 : retransmise\n";
					#open (MODIFIED, ">>tab.txt");
					#print MODIFIED $request->as_string."\n";
					#print MODIFIED $response->as_string."\n";
					#close MODIFIED;
					print "COOKIE dans la boucle code : ".$response->header("Set-Cookie")."\n";
					goto CHECK_CODE;
				}
			}

			if($response->code == 302){
				print "Checking new location...\n";
				print "Renvoi de la requete : 302\n";
				
				#if($response->header("Location") =~ /(((https:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/){
					#$response->header("Location") =~ s/https/http/;
					$request->uri("");
					$request->uri($response->header("Location").$request->uri);
					print "Renvoi de la requete : 302\n";
					#$request->uri($response->header("Location").$request->uri);
					print "URL envoyé : ".$request->uri."\n";
					if($response = $ua->request( $request )){
						print "Requete 302 : retransmise\n";
						open (MODIFIED, ">>tab.txt");
						print MODIFIED $request->as_string."\n";
						print MODIFIED $response->as_string."\n";
						close MODIFIED;
						goto CHECK_CODE;
					}
			}
			
			

			#if ($response->content =~ m/https:\/\//){
				#print "https trouvé!!\n\n\n\n\n";
				

				#if(my $content_encoding = $response->header("Content-Encoding")){
				#	print "La methode d encodage est  :  $content_encoding\n\n\n\n";
				#	$tmp = $response->decoded_content($content_encoding);
				#}else{
				#	$tmp = $response->decoded_content("UTF-8");
				#}
				$tmp = $response->decoded_content;
				open (SOURCE, ">>source.html");
				print SOURCE $tmp;
				close SOURCE;
				
				
				
				open (MODIFIED, ">>modified.html");
				if($tmp =~ /((([A-Za-z]{3,9}:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/g){
					print MODIFIED "$&\n";
					$tmp =~ s/https/http/g;
				}
				close MODIFIED;
				
			#$c->send_basic_header( $response->status_line );
			#$c->send_file_response( "modified.html" );
			#$c->send_status_line( "200" );
			#$c->send_header("Content-Type",$response->header("Content-Type"));
			#$c->send_header("Content-Length",length($tmp));
			#$c->send_crlf();
			#$c->send_response("RESP HIERE");
				if($response->header("Connection")){
					print "serveur : ".$response->header("Connection")."\n";
				}
				if(!$response->status_line){
					$response->status_line = "200 OK";
				}
				print "COOKIE avant l'envoi : ".$response->header("Set-Cookie")."\n";
				#print "Content-type : ".$response->header("Content-Type")."\n";
				#print "Content-Length: ".length($tmp)."\n";
				#print "Status-Line: ".$response->status_line."\n";
				#print "Connection: ".$response->header("Connection")."\n";
				#print $tmp;
	
				
				if($response->header("Set-Cookie")){
					if($c->send_response($response->status_line."\r\nServer: KIKOULOL/0.0\r\nContent-Type : ".$response->header("Content-Type")
					."\r\nContent-Length: ".length($tmp)."\r\nSet-Cookie: ".$response->header("Set-Cookie")."\r\nConnection: ".$response->header("Connection")."\r\n\r\n".$tmp)){
						print "Réponse envoyée au client ac cookie\n";
					}else{
						print "\nRéponse non envoyé au client ac cookie\ndernier eval: $?\nerreur : $!";
					}
				}else{
					if($c->send_response($response->status_line."\r\nServer: KIKOULOL/0.0\r\nContent-Type : ".$response->header("Content-Type")
					."\r\nContent-Length: ".length($tmp)."\r\nConnection: ".$response->header("Connection")."\r\n\r\n".$tmp)){
						print "Réponse envoyée au client sans cookie\n";
					}else{
						print "\nRéponse non envoyé au client sans cookie\n";
					}
				}
		}
		print "Fin d'envoi au client.\n\n";
		$c->close;
		undef($c);	
		
		print "En attente d'une requête\n";
}


