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
	$self = $self->SUPER::new(%settings);

	#CAS attributes
	$self->{'pgt'} = $settings{'pgt'};
	$self->{'casServer'} = $settings{'casServer'};
	$self->{'casServer'} =~ s/\/*$//og;

	#add proxy request callback handler is casServer and PGT are set
	if($self->{'pgt'} && $self->{'casServer'}) {
		$self->set_my_handler('response_redirect', \&casProxyRequest,
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
sub _isCASLoginURI($$) {
	my $self = shift;
	my ($targetURI) = @_;

	#make targetURI a URI object and clean off un-necessary params
	$targetURI = URI->new($targetURI);
	$targetURI->fragment(undef);
	$targetURI->query(undef);

	#test if URI is for the cas login page
	return $targetURI->eq($self->{'casServer'} . '/login');
}

#method to get a PT for the specified service
sub getPT($$) {
	my $self = shift;
	my ($service) = @_;

	if($service && $self->{'pgt'} && $self->{'casServer'}) {
		my $PT_url = URI
			->new($self->{'casServer'} . '/proxy')
			->canonical;
		$PT_url->query_form('targetService', $service, 'pgt', $self->{'pgt'});
		my $response = $self->simple_request(HTTP::Request->new('GET' => $PT_url));
		#if proxy ticket is retrieved successfully, return it
		if($response->content =~ /<cas:proxyTicket>(.*?)<\/cas:proxyTicket>/o) {
			return $1;
		}
	}

	return;
}

##Callback functions

#callback that will handle retrieving a CAS PT and reissue the original request
sub casProxyRequest($$$) {
	my ($response, $ua, $h) = @_;

	#check to see if CAS attributes are defined before proceeding
	if($ua->{'pgt'} && $ua->{'casServer'}) {
		my $request = $response->request;
		my $targetURI = URI->new_abs(scalar $response->header('Location'), $request->uri)->canonical;

		#CAS redirection?
		if($ua->_isCASLoginURI($targetURI)) {
			#find the requested service name
			my $service = $targetURI->query_param('service');

			#short-circuit if no service is found
			return if(!$service);

			#if a proxy ticket is retrieved successfully, reissue initial request with the proxy ticket
			my $ticket = $ua->getPT($service);
			if($ticket) {
				my $newURI = URI->new($service . ($service =~ /\?/o ? '&' : '?') . 'ticket=' . $ticket);
				#update the Location header in the response
				$response->header('Location' => $newURI->as_string);

				#if the service is the same as the original request uri, reissue the request to keep any request content
				if($request->uri->eq($service)) {
					my $newRequest = $request->clone;
					$newRequest->uri($newURI);
					return $newRequest;
				}
			}
		}
	}

	#use default processing
	return;
}

1;
