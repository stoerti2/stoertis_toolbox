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
use Term::ANSIColor qw(:constants);
use JSON::PP;
use URI::Escape;
use HTTP::Request;
use HTTP::Response;

# ======================================================================
# HTTP VERB TESTER (Methoden & XST)
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet welche HTTP-Methoden auf einem Webserver erlaubt sind
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet:
#   • Standard-Methoden (GET, POST, HEAD)
#   • Riskante Methoden (PUT, DELETE, TRACE, CONNECT)
#   • WebDAV-Methoden (PROPFIND, COPY, MOVE, LOCK)
#   • XST (Cross-Site Tracing) via TRACE
#   • PUT Upload-Möglichkeiten
# ======================================================================

# Farben
my $GREEN = GREEN;
my $RED = RED;
my $YELLOW = YELLOW;
my $CYAN = CYAN;
my $RESET = RESET;

# ======================================================================
# KONFIGURATION
# ======================================================================
my %config = (
    target_url      => '',
    timeout         => 10,
    verbose         => 0,
    quiet           => 0,
    output_json     => '',
    user_agent      => 'Mozilla/5.0 (HTTP Verb Tester)',
    delay           => 0.2,
    follow_redirects => 0,
    cookie          => '',
    auth_user       => '',
    auth_pass       => '',
    test_file       => 'test.txt',
    test_content    => 'HTTP Verb Tester Test Content',
    check_webdav    => 0,
    check_xst       => 1,
    test_upload     => 0,
    output_format   => 'text',
    dangerous       => 0,  # Wirklich gefährliche Methoden testen (DELETE)
);

# ======================================================================
# HTTP METHODEN
# ======================================================================
my @safe_methods = qw(
    GET
    HEAD
    POST
    OPTIONS
);

my @risky_methods = qw(
    PUT
    DELETE
    TRACE
    CONNECT
    PATCH
);

my @webdav_methods = qw(
    PROPFIND
    PROPPATCH
    MKCOL
    COPY
    MOVE
    LOCK
    UNLOCK
    SEARCH
);

my @other_methods = qw(
    PURGE
    LINK
    UNLINK
    VIEW
);

# Alle Methoden für den Test
my @all_methods = (
    @safe_methods,
    @risky_methods,
    ($config{check_webdav} ? @webdav_methods : ()),
    ($config{check_webdav} ? @other_methods : ()),
);

# ======================================================================
# KOMMANDOZEILENOPTIONEN
# ======================================================================
GetOptions(
    'url=s'           => \$config{target_url},
    'timeout=i'       => \$config{timeout},
    'verbose'         => \$config{verbose},
    'quiet'           => \$config{quiet},
    'output=s'        => \$config{output_json},
    'user-agent=s'    => \$config{user_agent},
    'delay=f'         => \$config{delay},
    'follow-redirects'=> \$config{follow_redirects},
    'cookie=s'        => \$config{cookie},
    'auth=s'          => \$config{auth_user},
    'auth-pass=s'     => \$config{auth_pass},
    'check-webdav'    => \$config{check_webdav},
    'no-xst'          => sub { $config{check_xst} = 0 },
    'test-upload'     => \$config{test_upload},
    'file=s'          => \$config{test_file},
    'content=s'       => \$config{test_content},
    'dangerous'       => \$config{dangerous},
    'format=s'        => \$config{output_format},
    'help'            => sub { print_help(); exit 0; }
) or die "Fehler in Optionen. Verwende --help\n";

# ======================================================================
# VALIDIERUNG
# ======================================================================
validate_config();

# ======================================================================
# INITIALISIERUNG
# ======================================================================
my $start_time = time();
my %results = ();
my @allowed_methods = ();
my @disallowed_methods = ();
my @interesting_findings = ();

show_banner();
print_info("Ziel: $config{target_url}");
print_info("Timeout: $config{timeout} Sekunden");
print_info("Teste " . scalar(@all_methods) . " HTTP-Methoden");

# User-Agent erstellen
my $ua = create_user_agent();

# ======================================================================
# 1. BASIS-CHECK (OPTIONS)
# ======================================================================
print_section("OPTIONS METHODE");

my $options_result = test_method('OPTIONS', '');
if ($options_result->{success}) {
    print_success("OPTIONS erfolgreich");

    # Allow-Header parsen
    if ($options_result->{headers}->{allow}) {
        my $allow = $options_result->{headers}->{allow};
        print_info("Allow: $allow");

        # Zusätzliche Methoden aus Allow-Header
        my @header_methods = split(/,\s*/, $allow);
        foreach my $method (@header_methods) {
            $method = uc($method);
            if (!grep { $_ eq $method } @all_methods) {
                print_info("  → Zusätzliche Methode: $method");
                push @all_methods, $method;
            }
        }
    }
} else {
    print_warning("OPTIONS nicht verfügbar (HTTP " . $options_result->{code} . ")");
}

# ======================================================================
# 2. ALLE METHODEN TESTEN
# ======================================================================
print_section("HTTP METHODEN TEST");

# Entferne Duplikate
my %seen;
my @unique_methods = grep { !$seen{$_}++ } @all_methods;

foreach my $method (@unique_methods) {
    print "  Teste: $method...\r" if $config{verbose};

    my $result = test_method($method, '');
    $results{$method} = $result;

    if ($result->{allowed}) {
        push @allowed_methods, $method;

        my $color = is_dangerous_method($method) ? $RED : $YELLOW;
        print_color("$color  → $method: ERLAUBT (HTTP $result->{code})$RESET");

        # Zusätzliche Tests für bestimmte Methoden
        if ($method eq 'TRACE' && $config{check_xst}) {
            test_xst_vulnerability();
        }
        if ($method eq 'PUT' && $config{test_upload}) {
            test_put_upload();
        }
    } else {
        push @disallowed_methods, $method;
        print_info("  → $method: NICHT ERLAUBT (HTTP $result->{code})") if $config{verbose};
    }

    sleep($config{delay}) if $config{delay} > 0;
}

print "\n" if $config{verbose};

# ======================================================================
# 3. XST (CROSS-SITE TRACING) TEST
# ======================================================================
if ($config{check_xst} && grep { $_ eq 'TRACE' } @allowed_methods) {
    print_section("XST (CROSS-SITE TRACING)");
    test_xst_vulnerability();
}

# ======================================================================
# 4. PUT UPLOAD TEST
# ======================================================================
if ($config{test_upload} && grep { $_ eq 'PUT' } @allowed_methods) {
    print_section("PUT UPLOAD TEST");
    test_put_upload();
}

# ======================================================================
# 5. ERGEBNISSE ANZEIGEN
# ======================================================================
print_section("ERGEBNISSE");

show_results();

# ======================================================================
# 6. RISIKOBEWERTUNG
# ======================================================================
my $risk_score = assess_risk();

# ======================================================================
# 7. OUTPUT SPEICHERN
# ======================================================================
if ($config{output_json}) {
    save_output($risk_score);
}

# ======================================================================
# 8. EMPFEHLUNGEN
# ======================================================================
print_recommendations($risk_score);

# ======================================================================
# ABSCHLUSS
# ======================================================================
my $total_time = time() - $start_time;
print_info(sprintf("Gesamtzeit: %.2f Sekunden", $total_time));
print_info("Erlaubte Methoden: " . scalar(@allowed_methods));

exit($risk_score > 5 ? 2 : ($risk_score > 2 ? 1 : 0));

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub validate_config {
    if (!$config{target_url}) {
        print_error("Keine Ziel-URL angegeben");
        print "Verwendung: $0 --url https://example.com [Optionen]\n";
        exit 1;
    }

    $config{target_url} =~ s/\/$//;
    if ($config{target_url} !~ /^https?:\/\//) {
        $config{target_url} = 'https://' . $config{target_url};
        print_warning("URL zu https:// ergänzt");
    }
}

sub create_user_agent {
    my $ua = LWP::UserAgent->new(
        timeout => $config{timeout},
        agent => $config{user_agent},
        max_size => 1024 * 1024,
        keep_alive => 0,
        max_redirect => $config{follow_redirects} ? 5 : 0,
        cookie_jar => {},
    );

    $ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0);

    if ($config{auth_user} && $config{auth_pass}) {
        $ua->credentials($config{target_url}, '', $config{auth_user}, $config{auth_pass});
    }

    if ($config{cookie}) {
        $ua->default_header('Cookie' => $config{cookie});
    }

    $ua->default_header('Accept' => '*/*');

    return $ua;
}

sub test_method {
    my ($method, $content) = @_;

    my $url = $config{target_url};
    my $req = HTTP::Request->new($method => $url);

    # Für PUT-Requests Inhalt hinzufügen
    if ($method eq 'PUT' && $content) {
        $req->content_type('text/plain');
        $req->content($content);
    }

    my $resp = $ua->request($req);

    my $result = {
        method => $method,
        code => $resp->code,
        message => $resp->message,
        success => $resp->is_success ? 1 : 0,
        allowed => 0,
        headers => {},
    };

    # Welche Statuscodes zeigen Erlaubnis an?
    # 200, 201, 204, 403, 405 sind typisch
    if ($resp->code == 200 || $resp->code == 201 || $resp->code == 204) {
        $result->{allowed} = 1;
    } elsif ($resp->code == 403 || $resp->code == 405) {
        $result->{allowed} = 0;
    } elsif ($resp->code == 500) {
        # Server-Fehler könnte auf erlaubte Methode hindeuten
        $result->{allowed} = 0;
        $result->{note} = "Server-Fehler (möglicherweise erlaubt?)";
    }

    # Wichtige Header speichern
    foreach my $header ($resp->header_field_names) {
        $result->{headers}{lc($header)} = $resp->header($header);
    }

    return $result;
}

sub test_xst_vulnerability {
    my $url = $config{target_url};
    my $req = HTTP::Request->new('TRACE' => $url);

    # XST-spezifische Header
    $req->header('X-Forwarded-For' => '127.0.0.1');
    $req->header('X-Forwarded-Host' => 'localhost');
    $req->header('X-Originating-IP' => '[::1]');

    my $resp = $ua->request($req);

    if ($resp->is_success) {
        my $content = $resp->content;

        # Prüfen ob der Request im Response reflektiert wird
        if ($content =~ /TRACE|X-Forwarded-For|127\.0\.0\.1/i) {
            print_color("$RED  → XST (Cross-Site Tracing) VERWUNDBAR!$RESET");
            push @interesting_findings, {
                type => 'xst',
                description => 'TRACE-Methode reflektiert Header - XST möglich',
                severity => 'high',
            };
        } else {
            print_warning("  → TRACE erlaubt, aber keine Reflexion (XST nicht möglich)");
        }
    }
}

sub test_put_upload {
    my $test_file = $config{test_file};
    my $test_content = $config{test_content};

    print_info("Teste PUT Upload mit Datei: $test_file");

    # Test 1: Einfacher Upload
    my $url1 = "$config{target_url}/$test_file";
    my $req1 = HTTP::Request->new('PUT' => $url1);
    $req1->content_type('text/plain');
    $req1->content($test_content);

    my $resp1 = $ua->request($req1);

    if ($resp1->is_success || $resp1->code == 201) {
        print_color("$RED  → PUT UPLOAD MÖGLICH! Datei erstellt: $test_file$RESET");

        # Prüfen ob Datei abrufbar
        my $get_req = HTTP::Request->new('GET' => $url1);
        my $get_resp = $ua->request($get_req);

        if ($get_resp->is_success && $get_resp->content eq $test_content) {
            print_color("$RED  → Datei ist öffentlich lesbar!$RESET");
            push @interesting_findings, {
                type => 'put_upload',
                description => "PUT Upload möglich, Datei $test_file erstellt und lesbar",
                severity => 'critical',
                url => $url1,
            };
        }
    }

    # Test 2: Upload in Unterverzeichnis
    my $url2 = "$config{target_url}/uploads/$test_file";
    my $req2 = HTTP::Request->new('PUT' => $url2);
    $req2->content_type('text/plain');
    $req2->content($test_content);

    my $resp2 = $ua->request($req2);

    if ($resp2->is_success || $resp2->code == 201) {
        print_color("$YELLOW  → PUT in Unterverzeichnis möglich: /uploads/$test_file$RESET");
    }

    # Test 3: PHP-Test (wenn gefährlich erlaubt)
    if ($config{dangerous}) {
        my $php_file = 'test.php';
        my $php_content = '<?php echo "HTTP Verb Tester"; ?>';

        my $url3 = "$config{target_url}/$php_file";
        my $req3 = HTTP::Request->new('PUT' => $url3);
        $req3->content_type('application/x-httpd-php');
        $req3->content($php_content);

        my $resp3 = $ua->request($req3);

        if ($resp3->is_success || $resp3->code == 201) {
            print_color("$RED🔴 PHP-UPLOAD MÖGLICH!$RESET");
            push @interesting_findings, {
                type => 'php_upload',
                description => "PHP-Datei per PUT uploadbar - RCE möglich!",
                severity => 'critical',
                url => $url3,
            };
        }
    }
}

sub is_dangerous_method {
    my ($method) = @_;

    my @dangerous = qw(PUT DELETE TRACE CONNECT PROPFIND MKCOL COPY MOVE LOCK);
    return grep { $_ eq $method } @dangerous;
}

sub show_results {
    print "\n" . "=" x 60 . "\n";
    print "HTTP METHODEN TEST ERGEBNISSE:\n";
    print "=" x 60 . "\n";

    print "\nERLAUBTE METHODEN (" . scalar(@allowed_methods) . "):\n";
    if (@allowed_methods) {
        foreach my $method (sort @allowed_methods) {
            my $color = is_dangerous_method($method) ? $RED : $GREEN;
            my $note = is_dangerous_method($method) ? " ⚠️  RISKANT!" : "";
            print_color("$color  • $method$RESET$note");
        }
    } else {
        print "  Keine erlaubten Methoden gefunden (außer OPTIONS)\n";
    }

    if (@interesting_findings) {
        print "\n" . "-" x 40 . "\n";
        print "INTERESSANTE FUNDE:\n";

        foreach my $finding (@interesting_findings) {
            my $color = $finding->{severity} eq 'critical' ? $RED : $YELLOW;
            print_color("$color  • $finding->{description}$RESET");
            print "    $finding->{url}\n" if $finding->{url};
        }
    }
}

sub assess_risk {
    my $score = 0;

    # Riskante Methoden bewerten
    foreach my $method (@allowed_methods) {
        if ($method eq 'PUT') {
            $score += 3;
            print_warning("PUT erlaubt - Datei-Upload möglich");
        }
        if ($method eq 'DELETE') {
            $score += 3;
            print_warning("DELETE erlaubt - Dateien können gelöscht werden");
        }
        if ($method eq 'TRACE') {
            $score += 2;
            print_warning("TRACE erlaubt - XST möglich");
        }
        if ($method eq 'CONNECT') {
            $score += 2;
            print_warning("CONNECT erlaubt - Proxy-Funktionalität");
        }
    }

    # XST-Funde
    if (grep { $_->{type} eq 'xst' } @interesting_findings) {
        $score += 3;
    }

    # PUT Upload-Funde
    if (grep { $_->{type} eq 'put_upload' } @interesting_findings) {
        $score += 4;
    }
    if (grep { $_->{type} eq 'php_upload' } @interesting_findings) {
        $score += 5;
    }

    print "\n" . "=" x 60 . "\n";
    print "RISIKO-SCORE: $score/10\n";

    if ($score >= 7) {
        print_color("$RED🔴 KRITISCH: Server ist stark gefährdet!$RESET");
    } elsif ($score >= 4) {
        print_color("$YELLOW🟡 MITTEL: Riskante HTTP-Methoden erlaubt$RESET");
    } else {
        print_color("$GREEN🟢 GERING: Server gut konfiguriert$RESET");
    }

    return $score;
}

sub save_output {
    my ($score) = @_;

    my $output = {
        tool => "HTTP Verb Tester",
        version => "1.0",
        timestamp => scalar(localtime()),
        target => $config{target_url},
        config => \%config,
        statistics => {
            total_tested => scalar(keys %results),
            allowed => scalar(@allowed_methods),
            disallowed => scalar(@disallowed_methods),
            dangerous_allowed => scalar(grep { is_dangerous_method($_) } @allowed_methods),
        },
        allowed_methods => \@allowed_methods,
        disallowed_methods => \@disallowed_methods,
        interesting_findings => \@interesting_findings,
        risk_score => $score,
        risk_level => $score >= 7 ? "CRITICAL" : ($score >= 4 ? "MEDIUM" : "LOW"),
        total_time => time() - $start_time,
    };

    if ($config{output_format} eq 'json' || $config{output_json} =~ /\.json$/) {
        my $json = JSON::PP->new->pretty->encode($output);
        open(my $fh, '>', $config{output_json}) or die "Kann Datei nicht öffnen: $!";
        print $fh $json;
        close($fh);
        print_success("JSON gespeichert: $config{output_json}");
    }
}

sub print_recommendations {
    my ($score) = @_;

    print_section("EMPFEHLUNGEN");

    my @recs = (
        "• Nicht benötigte HTTP-Methoden deaktivieren",
        "• Für Apache: LimitExcept in .htaccess",
        "  <LimitExcept GET POST HEAD>",
        "      Require all denied",
        "  </LimitExcept>",
        "• Für Nginx: limit_except Direktive",
        "• PUT/DELETE nur mit Authentifizierung erlauben",
        "• TRACE-Methode komplett deaktivieren",
        "• WebDAV-Methoden nur bei Bedarf aktivieren",
    );

    if (grep { $_ eq 'TRACE' } @allowed_methods) {
        unshift @recs, "🔴 TRACE-Methode deaktivieren (XST-Schwachstelle)";
    }

    if (grep { $_ eq 'PUT' } @allowed_methods) {
        unshift @recs, "🔴 PUT-Methode einschränken oder deaktivieren";
    }

    if (grep { $_ eq 'DELETE' } @allowed_methods) {
        unshift @recs, "🔴 DELETE-Methode deaktivieren";
    }

    foreach (@recs) {
        print "$_\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
HTTP VERB TESTER v1.0 (Methoden & XST)
================================================================================

BESCHREIBUNG:
  Testet welche HTTP-Methoden auf einem Webserver erlaubt sind und prüft
  auf Sicherheitsrisiken wie XST (Cross-Site Tracing) oder PUT-Uploads.

GETESTETE METHODEN:
  • Standard: GET, POST, HEAD, OPTIONS
  • Risikant: PUT, DELETE, TRACE, CONNECT, PATCH
  • WebDAV: PROPFIND, MKCOL, COPY, MOVE, LOCK (mit --check-webdav)

VERWENDUNG:
  $0 --url <ziel-url> [Optionen]

OPTIONEN:
  --url URL        Ziel-URL (z.B. https://example.com)

  --check-webdav   WebDAV-Methoden testen
  --test-upload    PUT-Upload praktisch testen
  --no-xst         XST-Test überspringen
  --dangerous      Wirklich gefährliche Tests (PHP-Upload)

  --file NAME      Test-Dateiname für PUT (Default: test.txt)
  --content TEXT   Test-Inhalt für PUT (Default: HTTP Verb Tester...)

  --timeout N      Timeout in Sekunden (Default: 10)
  --delay N        Pause zwischen Tests (Default: 0.2)
  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe
  --output DATEI   Ergebnisse als JSON speichern
  --format FORMAT  text, json (Default: text)

  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Standard-Test
  $0 --url https://example.com

  # Mit WebDAV-Check und PUT-Test
  $0 --url https://example.com --check-webdav --test-upload

  # Ausführlicher Test mit JSON-Output
  $0 --url https://example.com --verbose --output verbs.json

HINWEISE:
  • PUT/DELETE können Dateien verändern/löschen!
  • TRACE ermöglicht XST-Angriffe
  • Nur auf eigenen oder autorisierten Systemen testen!
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
HTTP VERB TESTER v1.0 (Methoden & XST)
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

sub print_color {
    my ($msg) = @_;
    print "$msg\n";
}

__END__
