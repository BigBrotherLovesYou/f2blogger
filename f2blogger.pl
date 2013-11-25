#!/usr/bin/perl
# Copyright Pablo Rönnebarth true1984 at gmail dot com
# GNU General Public License, version 3 (GPL-3.0)
# http://opensource.org/licenses/GPL-3.0
# simple script to watch the fail2ban log
# and output html with banned ips

=head#### TODO #########################



=cut####################################

use strict;
use warnings;
use lib 'libs';
use POE qw/Wheel::FollowTail/;

#use Text2::Markup;
use Geo::IP;
use Geo::CountryFlags;
use File::Pid::Quick qw( /var/run/f2blogger.pid verbose );
use DBI;
use Image::WorldMap;
use List::MoreUtils qw{ uniq };
use GD::Graph::pie;
use Config::IniFiles;

# make output unbuffered
$| = 1;

# script vars
my @coordinates;

#my ( $fh, $city, $country, $countrycode, $latitude, $longitude );
my $fh;

# check if already running
File::Pid::Quick->check('/var/run/f2blogger.pid');

# read config file
my $cfg = Config::IniFiles->new( -file => "f2blogger.conf" );

# Catch interrupts
# Catch <Ctrl>+c
$SIG{'INT'} = 'MySubs::int';

# Catch <Ctrl>+\
$SIG{'QUIT'} = 'MySubs::quit';

# startup
die "$0: f2blogger.conf: No such file or directory\n"
    unless -e "f2blogger.conf";
die "$0: f2blogger.conf: Permission denied\n"
    unless -r "f2blogger.conf";
die "$0: $cfg->val( 'logs', 'fail2banlog' ): No such file or directory\n"
    unless -e $cfg->val( 'logs', 'fail2banlog' );
die "$0: $cfg->val( 'logs', 'fail2banlog' ): Permission denied\n"
    unless -r $cfg->val( 'logs', 'fail2banlog' );
die "$0: $cfg->val( 'geoip', 'geolitedat' ): No such file or directory\n"
    unless -e $cfg->val( 'geoip', 'geolitedat' );
die "$0: $cfg->val( 'geoip', 'geolitedat' ): Permission denied\n"
    unless -r $cfg->val( 'geoip', 'geolitedat' );

# delete temporary files
prepare_files();

# prepare DB
my $dbh = DBI->connect( "dbi:mysql:$cfg->val( 'db', 'dbname' ):$cfg->val( 'db', 'dbip' )",
                        $cfg->val( 'db', 'dbuser' ),
                        $cfg->val( 'db', 'dbpass' ) )
    or die "Connection Error: $DBI::errstr\n";

# had some trouble with the DB connection timing out
$dbh->{mysql_auto_reconnect} = 1;

# create table
$dbh->do(
    "CREATE TABLE IF NOT EXISTS wannabe (id INTEGER(5) NOT NULL auto_increment,
                                      time VARCHAR(80) default NULL,
                                      date VARCHAR(80) default NULL,
                                      city VARCHAR(120) default NULL,
                                      country VARCHAR(120) default NULL,
                                      countrycode VARCHAR(40) default NULL,
                                      daemon VARCHAR(120) default NULL,
                                      ip VARCHAR(80) default NULL,
                                      latitude VARCHAR(80) default NULL,
                                      longitude VARCHAR(80) default NULL,
                                      KEY id (id),
                                      PRIMARY KEY (id)
                                      )" );

POE::Session->create(
    inline_states => {
        _start => sub {
            $_[HEAP]->{wheel} =
                POE::Wheel::FollowTail->new( Filename   => $_[ARG0],
                                             InputEvent => 'got_line',
                                             ErrorEvent => 'got_error',
                                             SeekBack   => 2048, );
            $_[HEAP]->{first} = 0;
        },
        got_line => sub {

            if ( $_[ARG0] =~ /Ban/ ) {

                # divide input
                # $banned[4]⁼daemon, $banned[6]=ip
                my @banned = split( / /, $_[ARG0] );
                my $daemon = $banned[4];
                my $date   = $banned[0];
                my $time   = $banned[1];
                my $ip     = $banned[6];

                # cut the []
                $daemon =~ s/^.(.*).$/$1/;

                # cut off milliseconds
                $time = substr $time, 0, 8;

                # write log
                if ($log_enabled) {
                    open( my $fhlog, '>>', $logfile )
                        or die("Could not open log file! Because: $!");
                    print $fhlog "$date $time $ip $daemon\n";
                    close($fhlog);
                }

                # check if the ip is internal
                if ( $ip =~ /"$cfg->val( 'internal_net', 'internal_ip' )"/ ) {
                    my $city    = "$cfg->val( 'internal_net', 'internal_city' )";
                    my $country = "$cfg->val( 'internal_net', 'internal_country' )";
                    my $countrycode =
                        "$cfg->val( 'internal_net', 'internal_countrycode' )";
                    my $ip = "internal_ip";

                    # where is the n00b
                } else {
                    my $gi = Geo::IP->open( "$cfg->val( 'geoip', 'geolitedat' )",
                                            GEOIP_STANDARD );
                    my $record = $gi->record_by_addr($ip);
                    $city        = $record->city;
                    $country     = $record->country_name;
                    $countrycode = $record->country_code;
                    my $latitude  = $record->latitude;
                    my $longitude = $record->longitude;
                }

                # insert into DB
                my $lastid =
                    new_wannabe( $dbh,      $time,        $date,   $city,
                                 $country,  $countrycode, $daemon, $ip,
                                 $latitude, $longitude );

                # get info from DB
                my $db_info = get_db_info($lastid);

                # create a fancy map
                create_map($db_info)
                    unless ( $ip eq "internal_ip" );

                # create a fancy pie chart \o/
                create_chart($db_info);

                # open file, count lines
                open( $fh, '<', $tmpfile ) or die("Could not open tmp file! Because: $!");
                @tmp_lines  = <$fh>;
                $line_count = @tmp_lines;
                close($fh);

                # is it the first line?
                if ( $line_count == "0" ) {

                    # if so write to tmp, write html
                    write_files( $date, $time, $ip, $city, $country, $daemon,
                                 $countrycode );

                    #print "linecount = " . $line_count . "\n";

                } else {

                    # is it less then 20 entries in tmpfile?
                    # if so do all stuff right away
                    if ( $line_count < $max_attackers ) {

                        #print "linecount2 = " . $line_count . "\n";
                        write_files( $date, $time, $ip, $city, $country, $daemon,
                                     $countrycode );

                    } else {

                        #print "linecount3 = " . $line_count . "\n";
                        # lets delete the first lines of $tmpfile
                        open( my $fh, '>', $tmpfile )
                            or die("Could not open tmp file! Because: $!");
                        my $startline = $line_count - $max_attackers;
                        for ( my $i = $startline ; $i < $line_count ; $i++ ) {

                            #print "line = " . $i . "\n";
                            #print $tmp_lines[$i] . "\n";
                            #print $fh "$tmp_lines[$i]" unless $tmp_lines[$i] == '';
                            print $fh "$tmp_lines[$i]";
                        }
                        close($fh);

                        # lets do the magic again
                        write_files( $date, $time, $ip, $city, $country, $daemon,
                                     $countrycode );
                    }
                }
            }
        },

        got_error => sub {
            warn "$_[ARG0]\n";
        }, },
    args => [ $cfg->val( 'logs', 'fail2banlog' ) ], );

sub get_db_info{
        my @results;
    my %freq;
    my $counter = "0";
    my @output_c;
    my @output_nr;

    # how many countries have we got?
    my $sql2 = "SELECT country FROM wannabe";
    my $sth2 = $dbh->prepare($sql2) or die "Couldn't prepare statement: " . $dbh->errstr;
    $sth2->execute() or die "Couldn't execute statement: " . $sth2->errstr;

    # get all countrycodes in DB, uniq them
    while ( my @data = $sth2->fetchrow_array() ) {
        push @results, $data[0];
    }
    @results = uniq @results;

    # how may have we got per country, excluding internal ips
    my $sql = 'SELECT * FROM wannabe WHERE country = ? AND NOT ip = "internal_ip"';
    my $sth = $dbh->prepare($sql) or die "Couldn't prepare statement: " . $dbh->errstr;
    foreach my $country (@results) {
        $sth->execute($country) or die "Couldn't execute statement: " . $sth->errstr;
        while ( my @data = $sth->fetchrow_array() ) {
            $freq{$country}++;
        }
    }

    my @countries = keys %freq;
    my @attacks   = values %freq;

    # now sort them, get the biggest perps
    # all the rest goes into others
    @countries = map $countries[$_],
        sort { $attacks[$b] <=> $attacks[$a] } 0 .. $#countries;
    foreach my $country (@countries) {
        if ( $counter < $cfg->val( 'output', 'nr_countries_for_pie' ) ) {
            $output_c[$counter]  = $country . ":" . $freq{$country};
            $output_nr[$counter] = $freq{$country};
        } elsif ( $counter == "$cfg->val( 'output', 'nr_countries_for_pie' )" ) {
            $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] = $freq{$country};
        } else {
            $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] =
                $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] +
                $freq{$country};
        }
        $counter++;
    }
    if ( $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] ) {
        $output_c[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] =
            "other:" . $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ];
    } else {
        $output_c[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] = "other:";
    }
}

sub write_files {
    my ( $date, $time, $ip, $city, $country, $daemon, $countrycode ) = @_;

    # get country flag
    my $gcf       = Geo::CountryFlags->new;
    my $flag_path = $gcf->get_flag($countrycode);
    my ( $directory, $flagname ) = $flag_path =~ m/(.*\/)(.*)$/;

    open( $fh, '>>', $tmpfile )
        or die("Could not open tmp file! Because: $!");
    if ($city) {
        print $fh '<center>'
            . "At $time, $date, $ip from $city, $country "
            . '<img title="cc" src="resources/flags/'
            . "$flagname"
            . '" width=30 height=19/>'
            . " trying to hack our $daemon.  "
            . '</center>' . "\n";
    } else {
        print $fh '<center>'
            . "At $time, $date, $ip from $country "
            . '<img title="cc" src="resources/flags/'
            . "$flagname"
            . '" width=30 height=19/>'
            . " trying to hack our $daemon.  "
            . '</center>' . "\n";
    }
    close($fh);
    my $parser = Text2::Markup->new( default_format   => 'textile',
                                     default_encoding => 'UTF-8', );
    my $html = $parser->parse( file => $tmpfile );
    open( my $fhhtml, '>', $output )
        or die("Could not open html file! Because: $!");
    print $fhhtml "$html\n";
    close($fhhtml);
}

sub prepare_files {

    #if ( -e $tmpfile ) {
    #    unlink $tmpfile or die("Could not delete tmp file! Because: $!");
    #}
    #open( $fh, '>', $tmpfile ) or die("Could not open tmp file! Because: $!");
    #close($fh);
    if ( -e $output ) {
        unlink $output or die("Could not delete html file! Because: $!");
        open( $fh, '>', $output ) or die("Could not open html file! Because: $!");
        close($fh);
        chown 33, 33, $output;
    }
}

sub new_wannabe {

    my ( $dbh,         $time,   $date, $city,     $country,
         $countrycode, $daemon, $ip,   $latitude, $longitude ) = @_;

    # check if the record already exists
    my $sql =
'SELECT * FROM wannabe WHERE ip = ? AND time = ? AND countrycode = ? AND daemon = ?';
    my $sth = $dbh->prepare($sql) or die "Couldn't prepare statement: " . $dbh->errstr;
    $sth->execute( $ip, $time, $countrycode, $daemon )    # Execute the query
        or die "Couldn't execute statement: " . $sth->errstr;

    # if not there insert into DB
    if ( $sth->rows == 0 ) {
        my $insert_handle =
            $dbh->prepare_cached('INSERT INTO wannabe VALUES (?,?,?,?,?,?,?,?)');
        die "Couldn't prepare queries; aborting" unless defined $insert_handle;

        $insert_handle->execute( "id", $time, $date, $city, $country, $countrycode,
                                 $daemon, $ip )
            or die "Couldn't insert data: " . $insert_handle->errstr;
        my $id = $dbh->last_insert_id();
        return $id;
    }
}

sub create_map {
    my ( $time, $daemon, $latitude, $longitude ) = @_;
    $time = substr( $time, 0, 5 );
    my $spot = join( '|', $time, $daemon, $latitude, $longitude );
    unshift( @coordinates, $spot );
    splice( @coordinates, $map_max_coord ) unless ( $#coordinates < $map_max_coord + 1 );

    # make the maps
    my $map     = Image::WorldMap->new( "earth-small.png", "FreeMono/10" );
    my $map_big = Image::WorldMap->new( "earth.png",       "FreeMono/35" );
    foreach my $spots (@coordinates) {
        my ( $time, $daemon, $latitude, $longitude ) = split( /\|/, $spots );
        $map->add( $longitude, $latitude, "$time", [ 255, 0, 0 ] );
        $map_big->add( $longitude, $latitude, "$time", [ 255, 0, 0 ] );
    }
    $map->draw($output_png);
    $map_big->draw($output_png_big);

}

sub create_chart2 {

    my @results;
    my %freq;

    # how many countries have we got?
    my $sql2 = "SELECT country FROM wannabe";
    my $sth2 = $dbh->prepare($sql2) or die "Couldn't prepare statement: " . $dbh->errstr;
    $sth2->execute() or die "Couldn't execute statement: " . $sth2->errstr;

    # get all countrycodes in DB, uniq them
    while ( my @data = $sth2->fetchrow_array() ) {
        push @results, $data[0];
    }
    @results = uniq @results;

    # how may have we got per country, excluding internal ips
    my $sql = 'SELECT * FROM wannabe WHERE country = ? AND NOT ip = "internal_ip"';
    my $sth = $dbh->prepare($sql) or die "Couldn't prepare statement: " . $dbh->errstr;
    foreach my $country (@results) {
        $sth->execute($country) or die "Couldn't execute statement: " . $sth->errstr;
        while ( my @data = $sth->fetchrow_array() ) {
            $freq{$country}++;
        }
    }

    my @countries = keys %freq;
    my @attacks   = values %freq;
    my @data      = ( \@countries, \@attacks );
    my $mygraph   = GD::Graph::pie->new( 300, 300 );
    $mygraph->set_title_font( 'FreeMono.ttf', 13 );
    $mygraph->set_label_font( 'FreeMono.ttf', 8 );
    $mygraph->set_value_font( 'FreeMono.ttf', 8 ); # does not seem to make a difference?
                                                   # title => 'Distribuiton of attackers',
    $mygraph->set( '3d' => 1, ) or warn $mygraph->error;
    my $myimage = $mygraph->plot( \@data ) or die $mygraph->error;
    open( my $img, '>', $pie_image ) or die $!;
    binmode $img;
    print $img $myimage->png;
}

sub create_chart {

    my @results;
    my %freq;
    my $counter = "0";
    my @output_c;
    my @output_nr;

    # how many countries have we got?
    my $sql2 = "SELECT country FROM wannabe";
    my $sth2 = $dbh->prepare($sql2) or die "Couldn't prepare statement: " . $dbh->errstr;
    $sth2->execute() or die "Couldn't execute statement: " . $sth2->errstr;

    # get all countrycodes in DB, uniq them
    while ( my @data = $sth2->fetchrow_array() ) {
        push @results, $data[0];
    }
    @results = uniq @results;

    # how may have we got per country, excluding internal ips
    my $sql = 'SELECT * FROM wannabe WHERE country = ? AND NOT ip = "internal_ip"';
    my $sth = $dbh->prepare($sql) or die "Couldn't prepare statement: " . $dbh->errstr;
    foreach my $country (@results) {
        $sth->execute($country) or die "Couldn't execute statement: " . $sth->errstr;
        while ( my @data = $sth->fetchrow_array() ) {
            $freq{$country}++;
        }
    }

    my @countries = keys %freq;
    my @attacks   = values %freq;

    # now sort them, get the biggest perps
    # all the rest goes into others
    @countries = map $countries[$_],
        sort { $attacks[$b] <=> $attacks[$a] } 0 .. $#countries;
    foreach my $country (@countries) {
        if ( $counter < $cfg->val( 'output', 'nr_countries_for_pie' ) ) {
            $output_c[$counter]  = $country . ":" . $freq{$country};
            $output_nr[$counter] = $freq{$country};
        } elsif ( $counter == "$cfg->val( 'output', 'nr_countries_for_pie' )" ) {
            $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] = $freq{$country};
        } else {
            $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] =
                $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] +
                $freq{$country};
        }
        $counter++;
    }
    if ( $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] ) {
        $output_c[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] =
            "other:" . $output_nr[ $cfg->val( 'output', 'nr_countries_for_pie' ) ];
    } else {
        $output_c[ $cfg->val( 'output', 'nr_countries_for_pie' ) ] = "other:";
    }

    my @data = ( \@output_c, \@output_nr );
    my $mygraph = GD::Graph::pie->new( 300, 300 );
    $mygraph->set_title_font( 'FreeMono.ttf', 13 );
    $mygraph->set_label_font( 'FreeMono.ttf', 8 );
    $mygraph->set_value_font( 'FreeMono.ttf', 8 ); # does not seem to make a difference?
                                                   # title => 'Distribuiton of attackers',
    $mygraph->set( '3d' => 1, ) or warn $mygraph->error;
    my $myimage = $mygraph->plot( \@data ) or die $mygraph->error;
    open( my $img, '>', $pie_image ) or die $!;
    binmode $img;
    print $img $myimage->png;
}

sub get_latest_inserts {
    my $last = $_;
    my $sql = 'SELECT * FROM wannabe WHERE id = ? AND NOT ip = "internal_ip"';
    my $sth = $dbh->prepare($sql) or die "Couldn't prepare statement: " . $dbh->errstr;
    foreach my $id ( reverse( $last - 6 .. $last ) ) {
        $sth->execute($id) or die "Couldn't execute statement: " . $sth->errstr;
        for ( my @data = $sth->fetchrow_array() ) {
            say;
        }
    }
}

# run main loop
$poe_kernel->run();

{    # here we make a new block MySubs

    package MySubs;

    # catch a ctrl+c, exit gracefully
    sub int {
        my $sig = @_;    # First argument is signal name
        print "Caught SIG $sig -- quitting\n";
        $SIG{'QUIT'} = 'DEFAULT';
        $SIG{'INT'}  = 'DEFAULT';
        if ( -e $tmpfile ) {
            unlink $tmpfile or die("Could not delete tmp file! Because: $!");
        }
        exit(0);
    }

    # catch a ctrl+\, exit gracefully
    sub quit {
        my $sig = @_;    # First argument is signal name
        print "Caught SIG $sig -- quitting\n";
        $SIG{'QUIT'} = 'DEFAULT';
        $SIG{'INT'}  = 'DEFAULT';
        if ( -e $tmpfile ) {
            unlink $tmpfile or die("Could not delete tmp file! Because: $!");
        }
        exit(0);
    }
}
