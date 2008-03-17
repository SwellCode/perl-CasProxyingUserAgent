package Authen::CAS::LWP::ProxyingUserAgent;

use strict;
use utf8;
use base qw{LWP::UserAgent};

our $VERSION = 0.02;

use LWP 5.805;
use URI;

sub new($%) {
	my ($class, %settings) = @_;
	my $self = $class->SUPER::new(%settings);

	#CAS attributes
	$self->{'pgt'} = $settings{'pgt'};
	$self->{'casServer'} = $settings{'casServer'};
	$self->{'casServer'} =~ s/\/*$//og;

	return $self;
}



##copied from LWP::UserAgent.pm and modified to include CAS code
##maybe move the CAS code to a more appropriate location in the LWP::UserAgent code in the future
sub request
{
	my($self, $request, $arg, $size, $previous) = @_;

	LWP::Debug::trace('()');

	my $response = $self->simple_request($request, $arg, $size);

	my $code = $response->code;
	$response->previous($previous) if defined $previous;

	LWP::Debug::debug('Simple response: ' .
	(HTTP::Status::status_message($code) ||
	"Unknown code $code"));

	if ($code == &HTTP::Status::RC_MOVED_PERMANENTLY or
	$code == &HTTP::Status::RC_FOUND or
	$code == &HTTP::Status::RC_SEE_OTHER or
	$code == &HTTP::Status::RC_TEMPORARY_REDIRECT)
	{
		my $referral = $request->clone;

		# These headers should never be forwarded
		$referral->remove_header('Host', 'Cookie');

		if ($referral->header('Referer') &&
		$request->url->scheme eq 'https' &&
		$referral->url->scheme eq 'http')
		{
			# RFC 2616, section 15.1.3.
			LWP::Debug::trace("https -> http redirect, suppressing Referer");
			$referral->remove_header('Referer');
		}

		# And then we update the URL based on the Location:-header.
		my $referral_uri = $response->header('Location');
		{
			# Some servers erroneously return a relative URL for redirects,
			# so make it absolute if it not already is.
			local $URI::ABS_ALLOW_RELATIVE_SCHEME = 1;
			my $base = $response->base;
			$referral_uri = "" unless defined $referral_uri;
			$referral_uri = $HTTP::URI_CLASS->new($referral_uri, $base)
			->abs($base);
		}
		$referral->url($referral_uri);

		# Check for loop in the redirects, we only count
		my $count = 0;
		my $r = $response;
		while ($r) {
			if (++$count > $self->{max_redirect}) {
				$response->header("Client-Warning" =>
				"Redirect loop detected (max_redirect = $self->{max_redirect})");
				return $response;
			}
			$r = $r->previous;
		}




		#####
		#####CAS redirection code
		#####
		#check to see if CAS variables are defined before proceeding
		if($self->{'pgt'} && $self->{'casServer'})
		{
			#initialize variables
			my $new_url = URI->new_abs(scalar $response->header('Location'),$request->url)->canonical;
			my $new_url2 = $new_url->clone;
			$new_url2->fragment(undef);
			$new_url2->query(undef);
			my $cas_url = URI->new($self->{'casServer'} . '/login')->canonical;

			#CAS redirection? if so, retrieve Proxy Ticket using PGT
			if($cas_url->eq($new_url2))
			{
				#retrieve the service name
				my @query_params = $new_url->query_form;
				my $service = undef;
				while(scalar @query_params && !defined $service)
				{
					my $key = shift @query_params;
					my $value = shift @query_params;
					if($key eq 'service')
					{
						$service = $value;
					}
				}

				#retrieve a proxy ticket for the service
				my $ticket = $self->getPT($service);

				#if a ticket is retrieved successfully, reissue initial request or issue a new request depending on the service URL
				if($ticket)
				{
					$new_url = URI->new($service . ($service =~ /\?/o ? '&' : '?') . 'ticket=' . $ticket);
					$new_url2 = URI->new($service);

					$referral->url($new_url);

					#if service is equal to the original request, force re-request because we recieved a valid ticket from CAS
					if($new_url2->eq($request->url))
					{
						return $self->request($referral, $arg, $size, $response);
					}
				}

			}
		}
		#####
		#####end of CAS redirection code
		#####


		#moved below CAS code so a CAS redirected POST can be re-issued if needed
		if ($code == &HTTP::Status::RC_SEE_OTHER ||
		$code == &HTTP::Status::RC_FOUND)
		{
			my $method = uc($referral->method);
			unless ($method eq "GET" || $method eq "HEAD") {
				$referral->method("GET");
				$referral->content("");
				$referral->remove_content_headers;
			}
		}

		return $response unless $self->redirect_ok($referral, $response);
		return $self->request($referral, $arg, $size, $response);
	}
	elsif ($code == &HTTP::Status::RC_UNAUTHORIZED ||
	$code == &HTTP::Status::RC_PROXY_AUTHENTICATION_REQUIRED
	)
	{
		my $proxy = ($code == &HTTP::Status::RC_PROXY_AUTHENTICATION_REQUIRED);
		my $ch_header = $proxy ?  "Proxy-Authenticate" : "WWW-Authenticate";
		my @challenge = $response->header($ch_header);
		unless (@challenge) {
			$response->header("Client-Warning" =>
			"Missing Authenticate header");
			return $response;
		}

		require HTTP::Headers::Util;
		CHALLENGE: for my $challenge (@challenge) {
			$challenge =~ tr/,/;/;  # "," is used to separate auth-params!!
			($challenge) = HTTP::Headers::Util::split_header_words($challenge);
			my $scheme = lc(shift(@$challenge));
			shift(@$challenge); # no value
			$challenge = { @$challenge };  # make rest into a hash
			for (keys %$challenge) {       # make sure all keys are lower case
				$challenge->{lc $_} = delete $challenge->{$_};
			}

			unless ($scheme =~ /^([a-z]+(?:-[a-z]+)*)$/) {
				$response->header("Client-Warning" =>
				"Bad authentication scheme '$scheme'");
				return $response;
			}
			$scheme = $1;  # untainted now
			my $class = "LWP::Authen::\u$scheme";
			$class =~ s/-/_/g;

			no strict 'refs';
			unless (%{"$class\::"}) {
				# try to load it
				eval "require $class";
				if ($@) {
					if ($@ =~ /^Can\'t locate/) {
						$response->header("Client-Warning" =>
						"Unsupported authentication scheme '$scheme'");
					}
					else {
						$response->header("Client-Warning" => $@);
					}
					next CHALLENGE;
				}
			}
			unless ($class->can("authenticate")) {
				$response->header("Client-Warning" =>
				"Unsupported authentication scheme '$scheme'");
				next CHALLENGE;
			}
			return $class->authenticate($self, $proxy, $challenge, $response,
			$request, $arg, $size);
		}
		return $response;
	}
	return $response;
}

sub getPT($$)
{
	my ($self, $service) = @_;

	if(defined $service && $self->{'pgt'} && $self->{'casServer'})
	{
		my $PT_url = URI
			->new($self->{'casServer'} . '/proxy')
			->canonical;
		$PT_url->query_form('targetService', $service, 'pgt', $self->{'pgt'});
		my $response = $self->simple_request(HTTP::Request->new('GET' => $PT_url));
		#if proxy ticket is retrieved successfully, return it
		if($response->content =~ /<cas:proxyTicket>(.*?)<\/cas:proxyTicket>/o)
		{
			return $1;
		}
		return '';
	}
	return undef;
}

1;
