#!/usr/bin/perl 
use strict;

use CGI::Carp q(fatalsToBrowser);
use Carp q(verbose);
use lib qw!/home/wakaba/work/manakai/lib /home/wakaba/work/charclass/lib!;
our $VERSION=do{my @r=(q$Revision: 1.3 $=~/\d+/g);sprintf "%d."."%02d" x $#r,@r};

sub get_resource ($) {
  require URI;
  my $uri = URI->new (shift);
  
  require Message::Util::HostPermit;
  my $host_permit = new Message::Util::HostPermit;
  $host_permit->add_rule (<<EOH);
Allow host=suika port=80
Deny host=suika
Allow host=suika.fam.cx port=80
Deny host=suika.fam.cx
Deny host=localhost
Deny host=*.localdomain
Deny ipv4=0.0.0.0/8
Deny ipv4=10.0.0.0/8
Deny ipv4=127.0.0.0/8
Deny ipv4=169.254.0.0/16
Deny ipv4=172.0.0.0/11
Deny ipv4=192.0.2.0/24
Deny ipv4=192.88.99.0/24
Deny ipv4=192.168.0.0/16
Deny ipv4=198.18.0.0/15
Deny ipv4=224.0.0.0/4
Deny ipv4=255.255.255.255/32
Deny ipv6=0::0/0
Deny host=*
EOH

  unless ({http => 1, https => 1}->{$uri->scheme}) {
    die "<$uri>: URI scheme not allowed";
  }

  if ($uri->can ('host')) {
    my ($host, $port) = ($uri->host, $uri->port);
    unless ($host_permit->check ($host, $port)) {
      die qq<<$uri>: "$host:$port": Host not allowed>;
    }
  }

  if ($uri->can ('path') and $uri->path =~ m#^/(?:~|%7E)wakaba/-temp/wiki#) {
    die qq<<$uri>: URI not allowed>;
  }
  
  require LWP::UserAgent;
  my $ua = LWP::UserAgent->new;
  $ua->agent ('slide-packer/' . $VERSION);
  	
  my $req = HTTP::Request->new (GET => $uri);
  my $res = $ua->request ($req);
  unless ($res->is_success) {
    die "<$uri>: ".$res->status_line;
  }
  
  my $real_uri = $res->request->uri;
  my $cbase_uri = URI->new ($res->header ('Content-Base'))->abs ($real_uri);
  my $cloc_uri = URI->new ($res->header ('Content-Location'))->abs ($cbase_uri);

  return {request_uri => $real_uri,
          base_uri => $cbase_uri,
          location_uri => $cloc_uri,
          media_type => $res->header ('Content-Type') ||
                        'text/plain; charset=iso-8859-1',
          body => $res->content};
  ## TODO: Last-Modified
  ## TODO: Content-Disposition filename
}

sub add_file ($$;%) {
  require File::Spec;
  my ($files, $rep, %opt) = @_;
  my $file_name;
  if ($rep->{location_uri} =~ m#([^/]+)/?$#) {
    $file_name = lc $1;
  } else {
    $file_name = lc $rep->{location_uri};
  }
  $file_name =~ s/[^a-z0-9._-]/_/g;
  $file_name =~ s/^\./_/;

  my $original_file_name = $file_name;
  my $i = 0;
  my $file_path;
  CHK: {
    for my $file (@$files) {
      if ($file->{file_name} eq $file_name) {
        $file_name = $original_file_name;
        $file_name =~ s/(?:(?=\.)|$)/++$i/;
        redo CHK;
      }
    }

    $file_path = File::Spec->catfile ($opt{base_directory} || '/', $file_name);
    if (-e $file_path) {
      $file_name = $original_file_name;
      $file_name =~ s/(?:(?=\.)|$)/++$i/;
      redo CHK;      
    }
  }
  $rep->{file_name} = $file_name;
  $rep->{file_path} = $file_path;
  require URI::file;
  $rep->{file_uri} = URI::file->new ($file_path);
  push @$files, $rep;
}

our $CheckDepth = 0;
sub check_referred_uris ($$%) {
  my ($files, $file, %opt) = @_;
  local $CheckDepth = $CheckDepth + 1;
  if ($CheckDepth == 15) {
    die "<$file->{uri}>: Links too deep";
  }
  if ($file->{media_type}
      =~ m#^\s*(?:application|text)/(?:xml|ht(?:c|ml)|[^+]\+xml)#i) {
    $file->{body} =~ s{
      \b ( (?: href | src | data ) = \s* ["'] ) ( [^\s"'>\#]+ ) () |
      (/\* \s* URI-reference== \s* \*/) [^']* '  ( [^\s'\#]+ ) ' [^']*
      (/\* \s* ==URI-reference \s* \*/)
    }{                            ## NOTE: If attribute name does 
                                  ##       followed by one or more Ses,
                                  ##       that reference has left unchanged.
      my $prev = $1 || $4 . q< '>;
      my $next = defined $3 ? $3 : q<' > . $6;
      my $uri = URI->new ($2 || $5)->abs ($file->{base_uri});
      my $rep = is_already_read ($files, $uri);
      unless ($rep) {
        $rep = get_resource ($uri);
        add_file ($files, $rep, %opt);
        check_referred_uris ($files, $rep, %opt);
      }
      $prev . URI->new ($rep->{file_uri})
                 ->rel ((defined $3 ? $file->{file_uri}
                                    : 'file:///')) . $next;
    }gex;
  } elsif ($file->{media_type} =~ m#^\s*text/css#) {
    $file->{body} =~ s{
        \b ( url\( '? ) ([^()']+) ( '? \) ) |
        ( \@import \s* ' ) ([^']+) ( ' )
    }{
      my $prev = $1 || $4;
      my $next = $3 || $6;
      my $uri = URI->new ($2 || $5)->abs ($file->{base_uri});
      my $fragment = $uri->fragment;
      $uri->fragment (undef);
      my $rep = is_already_read ($files, $uri);
      unless ($rep) {
        $rep = get_resource ($uri);
        add_file ($files, $rep, %opt);
        check_referred_uris ($files, $rep, %opt);
      }
      $prev . URI->new ($rep->{file_uri})
                 ->rel ($file->{file_uri}) .
      (defined $fragment ? '#' . $fragment : '') . $next;
    }gex;
  } else {
    info (qq{<$file->{location_uri}>: Unsupported media type "@{[
          $file->{media_type}]}"});
  }
}

sub is_already_read ($$) {
  my ($files, $uri) = @_;
  for my $file (@$files) {
    if ($file->{request_uri} eq $uri or
        $file->{location_uri} eq $uri) {
      return $file;
    }
  }
  return 0;
}

sub info ($) {
  print STDERR shift, "\n";
}

sub files_to_zip ($%) {
  my ($files, %opt) = @_;
  require Archive::Zip;
  my $tar = Archive::Zip->new;
  my @info;
  for my $file (@$files) {
    $tar->addString ($file->{body}, substr $file->{file_path}, 1);
    my $info = sprintf 'File "%s"
        Original URI <%s>
        Original Location URI <%s>
        Original Base URI <%s>
        Media Type "%s"', $file->{file_path}, $file->{request_uri},
          $file->{location_uri}, $file->{base_uri}, $file->{media_type};
    push @info, $info;
  }
  require File::Spec;
  $tar->addString (join ("\n\n", sort @info),
                   substr File::Spec->catfile ($opt{base_directory},
                                               'filelist.txt'), 1);
                   
  $tar;
}

sub files_to_mht ($%) {
  my ($files, %opt) = @_;
  require Message::Entity;
  my $msg = Message::Entity->new;
  my $hdr = $msg->header;
  my $ct = $hdr->field ('Content-Type');
  $ct->media_type ('multipart/related');
  $ct->parameter (type => 'text/html');
  $hdr->field ('User-Agent')->add ('slidepacker' => $VERSION);
  my $bodies = $msg->body;
  my @info;
  for my $file (@$files) {
    my $bodypart = $bodies->item ($bodies->count);
    my $bhdr = $bodypart->header;
    $bhdr->add ('Content-Type' => $file->{media_type});
    my $cd = $bhdr->field ('Content-Disposition');
    $cd->value ('inline');
    $cd->parameter (filename => substr $file->{file_path}, 1);
    $bhdr->add ('Content-Location' => 'http://www.example.com/'.
                                       substr $file->{file_path}, 1);
    $bodypart->body ($file->{body});
    my $info = sprintf 'File "%s"
        Original URI <%s>
        Original Location URI <%s>
        Original Base URI <%s>
        Media Type "%s"', $file->{file_path}, $file->{request_uri},
          $file->{location_uri}, $file->{base_uri}, $file->{media_type};
    push @info, $info;
  }
  $bodies->item (0)->header->field ('Content-Type')->media_type ('text/html');
  $bodies->epilogue (join ("\n\n", sort @info));
  $msg;
}

my $uri;
if ($ENV{QUERY_STRING} =~ /(?:^|[&;])start=([^&;]+)/) {
  $uri = $1;
  $uri =~ s/%([0-9A-Fa-f][0-9A-Fa-f])/chr hex $1/ge;
} else {
  print "Status: 400 Bad Request-URI query\n";
  die qq'<$ENV{REQUEST_URI}>: Bad Request-URI - "start" query parameter required';
}

my $rep = get_resource ($uri);
my @files;

add_file (\@files, $rep);

my $dir_path = '/' . $rep->{file_name};
$dir_path =~ s#\..*##g;
$dir_path .= '.files';

check_referred_uris (\@files, $rep, base_directory => $dir_path);

## MHT packed version
add_file (\@files, {
  body => files_to_mht (\@files, base_directory => $dir_path)->stringify,
  request_uri => URI->new ('file:///'.$rep->{file_name}),
  location_uri => URI->new ('file:///'.$rep->{file_name}.'.mht'),
  base_uri => URI->new ('file:///'.$rep->{file_name}.'.mht'),
  media_type => 'message/rfc822',
});

binmode STDOUT;

print "Content-Type: application/zip\n";
print "Content-Disposition: inline; filename=$rep->{file_name}.zip\n";
print "\n";

files_to_zip (\@files, base_directory => $dir_path)
  ->writeToFileHandle (\*STDOUT);

