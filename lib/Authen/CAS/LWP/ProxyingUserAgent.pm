package Authen::CAS::LWP::ProxyingUserAgent;

use strict;
use utf8;
use base qw{LWP::UserAgent};

our $VERSION = 0.03;

use HTTP::Status 5.811 ();
use LWP 5.815;
use URI;
use URI::QueryParam;

##Static Methods

#Constructor
sub new($%) {
	my $self = shift;
	my (%settings) = @_;

	#setup the base object
	$self = $self->SUPER::new(%settings);

	#CAS attributes
	if($settings{'casServer'} && $settings{'casPgt'}) {
		$self->{'casServer'} = URI->new($settings{'casServer'} . ($settings{'casServer'} =~ /\/$/o ? '' : '/'));
		$self->{'casPgt'} = $settings{'casPgt'};

		#add proxy request callback handler
		$self->set_my_handler('response_redirect',
			sub {
				my ($response, $ua) = @_;

				#check to see if CAS attributes are defined before proceeding
				if($ua->{'casPgt'} && $ua->{'casServer'}) {
					my $request = $response->request;
					my $targetUri = URI->new_abs(scalar $response->header('Location'), $request->uri)->canonical;

					#CAS redirection?
					if($ua->_isCasLoginUri($targetUri)) {
						#find the requested service name
						my $service = $targetUri->query_param('service');

						#short-circuit if no service is found
						return if(!$service);

						#if a proxy ticket is retrieved successfully, reissue initial request with the proxy ticket
						if(my $ticket = $ua->getPt($service)) {
							#generate the new uri
							my $uri = URI->new($service . ($service =~ /\?/o ? '&' : '?') . 'ticket=' . $ticket);

							#if the service is the same as the original request uri, reissue the request to keep any request content
							if($request->uri->eq($service)) {
								my $newRequest = $request->clone;
								$newRequest->uri($uri);
								return $newRequest;
							}
							#otherwise update the target location for the redirect response
							else {
								$response->header('Location' => $uri->as_string);
							}
						}
					}
				}

				#use default processing
				return;
			},
			'm_code' => [
				HTTP::Status::RC_MOVED_PERMANENTLY,
				HTTP::Status::RC_FOUND,
				HTTP::Status::RC_SEE_OTHER,
				HTTP::Status::RC_TEMPORARY_REDIRECT,
			],
		);
	}

	return $self;
}

##Instance Methods

#method that tests to see if the specified uri is a cas login uri
sub _isCasLoginUri($$) {
	my $self = shift;
	my ($uri) = @_;

	#cleanup $uri before testing to see if it's a cas login uri
	$uri = URI->new($uri);
	$uri->fragment(undef);
	$uri->query(undef);

	#test if $uri is for the cas login page
	return $uri->eq(URI->new_abs('login', $self->{'casServer'}));
}

#method to get and return a proxy ticket for the specified service
sub getPt($$) {
	my $self = shift;
	my ($service) = @_;

	#only process the request if there is a cas server and pgt defined for this object
	if($service && $self->{'casPgt'} && $self->{'casServer'}) {
		#create the request uri
		my $ptUri = URI
			->new(URI->new_abs('proxy', $self->{'casServer'}))
			->canonical;
		$ptUri->query_form('targetService', $service, 'pgt', $self->{'casPgt'});

		#fetch proxy ticket and return it if successful
		my $response = $self->simple_request(HTTP::Request->new('GET' => $ptUri));
		if($response->content =~ /<cas:proxyTicket>(.*?)<\/cas:proxyTicket>/o) {
			return $1;
		}
	}

	return;
}

1;
