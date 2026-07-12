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
use WWW::Shodan::API;     # Für Shodan-Integration
use IO::Socket::INET;     # Für direkte Port-Scans
use JSON;                 # Für API-Antworten
use LWP::UserAgent;       # Für HTTP-Anfragen
use Text::CSV;            # Für CSV-Export
use File::Basename;       # Für Dateipfade
use Time::Piece;          # Für Zeitstempel
use Sys::Hostname;        # Für Hostnamen
use Data::Dumper;         # Für Debugging
use Getopt::Long;         # Für Kommandozeilenoptionen

# =====================================================================================================================
# OpenClaw Finder
# Sucht OpenClaw Installationen im Internet
# =====================================================================================================================
# Autor:         Klaus Baumdick (stoerti) aka "The jobless hacker"
# Redesigned:    2026-03-06
# Lizenz:        CC BY-NC-ND 4.0
# Version:       2.0
# =====================================================================================================================
# Dieses Script darf NUR für Bildungszwecke verwendet werden!
# =====================================================================================================================
# Einfacher Start
# ./# Einfacher Start
# ./23_OpenClawScanner.pl

# Nur Shodan-Suche
# ./23_OpenClawScanner.pl --shodan-only

# Nur direkte Scans
# ./23_OpenClawScanner.pl --scan-only

# Mit ausführlicher Ausgabe
# ./23_OpenClawScanner.pl --verbose

# Eigene CSV-Datei
# ./23_OpenClawScanner.pl --output meine_funde.csv

# Hilfe anzeigen
# ./23_OpenClawScanner.pl --help

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Nach dem Fund ist vor dem Angriff
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Test auf 32 Angriffsvektoren
# Erkennt C2-Infrastruktur, AMOS Stealer, Reverse Shells, Credential Exfiltration, Memory Poisoning und CVE-2026-25253 (WebSocket-Hijacking)
# git clone https://github.com/adibirzu/openclaw-security-monitor.git
# cd openclaw-security-monitor
# ./scripts/scan.sh --target http://[IP]:18789
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Test auf 51 Angriffsvektoren
# git clone https://github.com/adversa-ai/secureclaw.git
# cd secureclaw
# bash skill/scripts/install.sh
# Audit durchführen
# bash ~/.openclaw/skills/secureclaw/scripts/quick-audit.sh --remote http://[IP]:18789
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Cisco AI Skill Scanner
# Installation
# pip install cisco-ai-skill-scanner
# Skill-Verzeichnis scannen (wenn zugänglich)
# skill-scanner scan /path/to/skills/ --use-behavioral --format table
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# JavaScript
# // In Browser-Konsole der Ziel-IP
# const ws = new WebSocket('ws://[IP]:18789');
# ws.onopen = () => {
#     console.log('🚨 Verbunden! Rate-Limiting?');
    # ws.send(JSON.stringify({type: 'auth', password: 'test'}));
# };
# Wenn die Verbindung sofort akzeptiert wird ohne Passwort-Brute-Force und ohne Rate-Limiting → KRITISCH verwundbar
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# curl -I http://[IP]:18789/openclaw.yaml
# curl -I http://[IP]:18789/.env
# curl -I http://[IP]:18789/healthz
# Wenn einer dieser Pfade zugänglich ist, liegen oft API-Keys und Tokens im Klartext
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Authentifizierungs-Bypass
# curl -X POST http://[IP]:18789/api/execute \
#   -H "Content-Type: application/json" \
#   -d '{"command": "ls -la"}'
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# ------------------------------------------------------------
# KONFIGURATION
# ------------------------------------------------------------
my $shodan_api_key      = "DEIN_SHODAN_API_KEY";      # https://account.shodan.io/register
my $openclaw_port       = 18789;                      # Standard-Port für OpenClaw Gateway
my $scan_timeout        = 3;                          # Timeout für Socket-Verbindungen (Sekunden)
my $http_timeout        = 5;                          # Timeout für HTTP-Anfragen (Sekunden)
my $pause_delay         = 0.1;                        # Pause zwischen Scans (DoS-Vermeidung)
my $max_concurrent      = 50;                         # Maximale parallele Scans
my $csv_datei           = "openclaw_funde.csv";       # CSV-Datei für Funde
my $log_datei           = "openclaw_scanner.log";     # Log-Datei
my $ip_liste_datei      = "ziel_ips.txt";             # Datei für manuelle IP-Listen
my $max_banner_laenge    = 1000;                       # Maximale Länge des Banners in CSV

# Globale Variablen
my $csv;                                                # CSV-Objekt
my @funde = ();                                         # Array für alle Funde
my $scan_start = localtime;                             # Startzeit des Scans

# ------------------------------------------------------------
# KOMMANDOZEILENOPTIONEN
# ------------------------------------------------------------
my $help = 0;
my $shodan_only = 0;
my $scan_only = 0;
my $verbose = 0;
my $output_file = $csv_datei;

GetOptions(
    'help|h'        => \$help,
    'shodan-only'   => \$shodan_only,
    'scan-only'     => \$scan_only,
    'verbose|v'     => \$verbose,
    'output|o=s'    => \$output_file,
) or usage();

sub usage {
    print "Usage: $0 [Optionen]\n";
    print "  --help, -h          Diese Hilfe anzeigen\n";
    print "  --shodan-only       Nur Shodan-Suche, keine direkten Scans\n";
    print "  --scan-only         Nur direkte Scans, keine Shodan-Suche\n";
    print "  --verbose, -v       Ausführliche Ausgaben\n";
    print "  --output, -o DATEI  CSV-Ausgabedatei (Standard: openclaw_funde.csv)\n";
    exit;
}

if ($help) {
    usage();
}

$csv_datei = $output_file if $output_file;

# ------------------------------------------------------------
# LOGGING-FUNKTION
# ------------------------------------------------------------
sub log_msg {
    my ($level, $msg) = @_;
    my $timestamp = localtime->strftime('%Y-%m-%d %H:%M:%S');
    my $log_entry = "[$timestamp] [$level] $msg";

    # Auf Bildschirm ausgeben
    print "$log_entry\n";

    # In Log-Datei schreiben
    open(my $log_fh, '>>', $log_datei) or warn "⚠️  Kann Log-Datei nicht öffnen: $!";
    print $log_fh "$log_entry\n";
    close($log_fh);
}

# ------------------------------------------------------------
# CSV-INITIALISIERUNG
# ------------------------------------------------------------
sub initialisiere_csv {
    my $datei = shift;

    # Prüfen ob Datei existiert
    my $datei_existiert = -e $datei;

    $csv = Text::CSV->new({
        binary => 1,
        eol => "\n",
        sep_char => ';',  # Semikolon als Trennzeichen (besser für Excel)
    }) or die "❌ Kann CSV-Objekt nicht erstellen: " . Text::CSV->error_diag();

    # Datei öffnen (append oder neu)
    my $mode = $datei_existiert ? '>>' : '>';
    open(my $fh, $mode, $datei) or die "❌ Kann CSV-Datei nicht öffnen: $!";

    # Header schreiben falls Datei neu ist
    if (!$datei_existiert) {
        my $header = [
            'ID', 'IP-Adresse', 'Port', 'Gefunden am', 'Quelle',
            'OpenClaw Version', 'Land', 'Status', 'Banner (gekürzt)',
            'HTTP-Status', 'Server-Header', 'SSL', 'Hostname',
            'Scan-Dauer (ms)', 'Wiederholungen'
        ];
        $csv->print($fh, $header);
        print $fh "\n";
    }

    close($fh);

    log_msg("INFO", "✅ CSV-Datei initialisiert: $datei");
}

# ------------------------------------------------------------
# FUND IN CSV SPEICHERN
# ------------------------------------------------------------
sub speichere_fund_csv {
    my ($fund) = @_;

    # ID generieren (einfach hochzählen)
    my $id = scalar(@funde) + 1;

    # Banner kürzen
    my $banner_kurz = substr($fund->{banner} // '', 0, $max_banner_laenge);
    $banner_kurz .= "..." if length($fund->{banner} // '') > $max_banner_laenge;

    # Zeile vorbereiten
    my $zeile = [
        $id,
        $fund->{ip},
        $fund->{port} // $openclaw_port,
        $fund->{timestamp} // localtime->strftime('%Y-%m-%d %H:%M:%S'),
        $fund->{quelle} // 'unbekannt',
        $fund->{version} // 'unbekannt',
        $fund->{land} // 'XX',
        $fund->{status} // 'neu',
        $banner_kurz,
        $fund->{http_status} // '',
        $fund->{server_header} // '',
        $fund->{ssl} ? 'ja' : 'nein',
        $fund->{hostname} // '',
        $fund->{scan_dauer} // '',
        $fund->{retries} // 0,
    ];

    # An CSV anhängen
    open(my $fh, '>>', $csv_datei) or warn "⚠️  Kann CSV nicht öffnen: $!";
    $csv->print($fh, $zeile);
    print $fh "\n";
    close($fh);

    # Im Speicher halten für Statistik
    push @funde, $fund;

    log_msg("FUND", "💾 $fund->{ip}:$fund->{port} ($fund->{version}) in CSV gespeichert");
}

# ------------------------------------------------------------
# FUNKTION 1: Shodan-API abfragen
# ------------------------------------------------------------
sub suche_mit_shodan {
    my ($api_key) = @_;

    unless ($api_key && $api_key ne "DEIN_SHODAN_API_KEY") {
        log_msg("WARNUNG", "⚠️  Kein gültiger Shodan-API-Key. Überspringe Shodan-Suche.");
        log_msg("INFO", "   Hol dir einen kostenlosen Key unter: https://account.shodan.io/register");
        return;
    }

    log_msg("INFO", "🔍 Durchsuche Shodan nach OpenClaw-Installationen (Port $openclaw_port)...");

    eval {
        # Shodan-API initialisieren
        my $shodan = WWW::Shodan::API->new($api_key);

        # Erweiterte Suchanfrage mit mehreren Indikatoren
        my $query = {
            port    => $openclaw_port,
            product => ['openclaw', 'gateway', 'api'],  # Mehrere Produkte
        };

        # Mehrere Seiten abrufen
        my $seite = 1;
        my $gesamt_gefunden = 0;

        while ($seite <= 5) {  # Maximal 5 Seiten (ca. 500 Ergebnisse)
            log_msg("INFO", "   Seite $seite abrufen...");

            my $result = $shodan->search($query, undef, { PAGE => $seite });
            last unless $result && ref($result) eq 'HASH';

            my $matches = $result->{'matches'} // [];
            my $total = $result->{'total'} // 0;

            log_msg("INFO", "   Seite $seite: " . scalar(@$matches) . " Ergebnisse");

            foreach my $host (@$matches) {
                my $ip = $host->{'ip_str'} // $host->{'ip'};
                my $port = $host->{'port'} // $openclaw_port;
                my $data = $host->{'data'} // '';
                my $location = $host->{'location'} // {};
                my $country = $location->{'country_code'} // 'XX';
                my $hostname = $host->{'hostnames'}->[0] // '';

                # Versuche OpenClaw-Version zu extrahieren
                my $version = "unbekannt";
                if ($data =~ /OpenClaw[\/\s]([\d\.]+)/i) {
                    $version = $1;
                } elsif ($data =~ /"version":\s*"([^"]+)"/) {
                    $version = $1;
                }

                # Zusätzliche Banner-Info
                my $http_status = $host->{'http'}->{'status'} // '';
                my $server_header = $host->{'http'}->{'server'} // '';
                my $ssl = $host->{'ssl'} ? 1 : 0;

                # Fund vorbereiten
                my $fund = {
                    ip           => $ip,
                    port         => $port,
                    timestamp    => localtime->strftime('%Y-%m-%d %H:%M:%S'),
                    quelle       => 'shodan',
                    version      => $version,
                    land         => $country,
                    status       => 'shodan_fund',
                    banner       => $data,
                    http_status  => $http_status,
                    server_header => $server_header,
                    ssl          => $ssl,
                    hostname     => $hostname,
                };

                speichere_fund_csv($fund);
                $gesamt_gefunden++;
            }

            $seite++;
            last if $seite > $result->{'pages'} // 0;
        }

        log_msg("INFO", "📊 Shodan: $gesamt_gefunden OpenClaw-Instanzen gespeichert");
    };

    if ($@) {
        log_msg("FEHLER", "❌ Fehler bei Shodan-API: $@");
    }
}

# ------------------------------------------------------------
# FUNKTION 2: HTTP-Banner abholen
# ------------------------------------------------------------
sub hole_banner {
    my ($ip, $port) = @_;

    my $ua = LWP::UserAgent->new(
        timeout => $http_timeout,
        max_redirect => 0,
    );
    $ua->agent("OpenClaw-Scanner/2.0 (Bildungszwecke; +https://github.com/stoerti/openclaw-finder)");

    # Versuche verschiedene Endpunkte
    my @urls = (
        "http://$ip:$port/",
        "http://$ip:$port/healthz",
        "http://$ip:$port/readyz",
        "http://$ip:$port/status",
        "http://$ip:$port/api/v1/health",
        "http://$ip:$port/metrics",
        "https://$ip:$port/",        # Auch HTTPS testen
        "https://$ip:$port/healthz",
    );

    my $ergebnis = {
        banner       => "Keine Antwort",
        http_status  => "",
        server_header => "",
        ssl          => 0,
        scan_dauer   => 0,
    };

    foreach my $url (@urls) {
        my $start = time;
        my $response = $ua->get($url);
        my $dauer = (time - $start) * 1000;  # in Millisekunden

        if ($response->is_success || $response->code == 401 || $response->code == 403) {
            $ergebnis->{banner} = $response->decoded_content // $response->content;
            $ergebnis->{http_status} = $response->code;
            $ergebnis->{server_header} = $response->header('Server') // '';
            $ergebnis->{ssl} = ($url =~ /^https/) ? 1 : 0;
            $ergebnis->{scan_dauer} = int($dauer);

            # Wenn wir eine erfolgreiche Antwort haben, brechen wir ab
            last if $response->is_success;
        }
    }

    return $ergebnis;
}

# ------------------------------------------------------------
# FUNKTION 3: Version aus Banner extrahieren
# ------------------------------------------------------------
sub extrahiere_version {
    my ($banner, $http_headers) = @_;

    # Verschiedene Versionierungsmuster
    if ($banner =~ /OpenClaw[\/\s]([\d\.]+)/i) {
        return $1;
    }
    elsif ($banner =~ /"version":\s*"([^"]+)"/) {
        return $1;
    }
    elsif ($banner =~ /Server:\s*OpenClaw[\/\s]([\d\.]+)/i) {
        return $1;
    }
    elsif ($banner =~ /X-Powered-By:\s*OpenClaw[\/\s]([\d\.]+)/i) {
        return $1;
    }
    elsif ($banner =~ /claw[\-\s]version[\-\s:]+([\d\.]+)/i) {
        return $1;
    }

    return "unbekannt";
}

# ------------------------------------------------------------
# FUNKTION 4: GeoIP-Land ermitteln
# ------------------------------------------------------------
sub hole_land_fuer_ip {
    my ($ip) = @_;

    # Option 1: Lokale GeoIP-Datenbank (falls vorhanden) - OHNE Konstanten
    if (-e "/usr/share/GeoIP/GeoIP.dat") {
        eval {
            require Geo::IP;
            # Einfache Methode ohne Konstanten - nur den Pfad übergeben
            my $geoip = Geo::IP->open("/usr/share/GeoIP/GeoIP.dat");
            if ($geoip) {
                my $country = $geoip->country_code_by_addr($ip);
                return $country if $country;
            }
        };
        # Wenn's nicht klappt, einfach ignorieren und weiter mit Option 2
    }

    # Option 2: Kostenloser Webservice (mit Cache) - funktioniert immer!
    return hole_land_per_webservice($ip);
}

# ------------------------------------------------------------
# FUNKTION 4b: GeoIP per Webservice
# ------------------------------------------------------------
sub hole_land_per_webservice {
    my ($ip) = @_;

    # Cache-Verzeichnis erstellen falls nötig
    my $cache_dir = "/tmp/geoip_cache";
    mkdir $cache_dir unless -d $cache_dir;

    my $cache_datei = "$cache_dir/geoip_$ip.txt";

    # Cache lesen (7 Tage gültig)
    if (-e $cache_datei && -M $cache_datei < 7) {
        open(my $fh, '<', $cache_datei) or return "XX";
        my $cached = <$fh>;
        close($fh);
        chomp $cached;
        return $cached if $cached && $cached ne "";
    }

    # Kostenlose Webservice-Abfrage (ip-api.com)
    eval {
        my $ua = LWP::UserAgent->new(
            timeout => 3,
            agent => 'Mozilla/5.0 (Kompatibel; GeoIP-Scanner/1.0)'
        );

        my $response = $ua->get("http://ip-api.com/json/$ip?fields=countryCode");

        if ($response->is_success) {
            my $data = decode_json($response->content);
            my $country = $data->{countryCode} // "XX";

            # Im Cache speichern
            open(my $fh, '>', $cache_datei) or return $country;
            print $fh $country;
            close($fh);

            return $country;
        }
    };

    # Fallback: Kein Land ermittelbar
    return "XX";
}

# ------------------------------------------------------------
# FUNKTION 5: IP-Liste aus Datei laden
# ------------------------------------------------------------
sub lade_ip_liste_aus_datei {
    my ($datei) = @_;

    my @ips;

    if (-e $datei) {
        open(my $fh, '<', $datei) or die "❌ Kann $datei nicht öffnen: $!";
        while (my $zeile = <$fh>) {
            chomp $zeile;
            $zeile =~ s/^\s+|\s+$//g;  # Trimmen
            next if $zeile =~ /^#/;     # Kommentare überspringen
            next if $zeile eq '';        # Leere Zeilen überspringen

            # IP-Adresse validieren (einfach)
            if ($zeile =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
                push @ips, $zeile;
            } else {
                log_msg("WARNUNG", "⚠️  Ungültige IP übersprungen: $zeile");
            }
        }
        close($fh);

        log_msg("INFO", "📁 $datei geladen: " . scalar(@ips) . " IPs");
    }

    return @ips;
}

# ------------------------------------------------------------
# FUNKTION 6: IP-Bereich generieren (CIDR-Notation)
# ------------------------------------------------------------
sub generiere_ip_bereich {
    my ($cidr) = @_;

    my @ips;

    if ($cidr =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/) {
        my $ip = $1;
        my $mask = $2;

        eval {
            require Net::IP;
            my $range = Net::IP->new($cidr);
            if ($range) {
                do {
                    push @ips, $range->ip();
                } while (++$range);
            }
        };

        if ($@) {
            log_msg("FEHLER", "❌ Fehler bei CIDR-Berechnung: $@");
        }
    }

    return @ips;
}

# ------------------------------------------------------------
# FUNKTION 7: Direkter Scan einer IP-Liste
# ------------------------------------------------------------
sub scanne_ip_liste {
    my ($ip_liste_ref, $quelle) = @_;
    my @ip_liste = @$ip_liste_ref;

    log_msg("INFO", "🔍 Scanne " . scalar(@ip_liste) . " IPs direkt nach Port $openclaw_port...");

    my $gefundene = 0;
    my $counter = 0;
    my $total = scalar(@ip_liste);

    foreach my $ip (@ip_liste) {
        $counter++;

        # Fortschritt anzeigen
        if ($verbose || $counter % 100 == 0) {
            log_msg("INFO", "   Fortschritt: $counter/$total IPs geprüft ($gefundene Funde)");
        }

        # Prüfe ob Port offen
        my $start = time;
        my $socket = IO::Socket::INET->new(
            PeerAddr  => $ip,
            PeerPort  => $openclaw_port,
            Proto     => 'tcp',
            Timeout   => $scan_timeout,
            Blocking  => 0,  # Nicht-blockierend
        );

        my $verbindungsdauer = (time - $start) * 1000;  # in Millisekunden

        if ($socket) {
            close($socket);
            log_msg("FUND", "   ✅ Port $openclaw_port offen auf $ip (${verbindungsdauer}ms)");

            # HTTP-Anfrage senden um Banner zu holen
            my $banner_info = hole_banner($ip, $openclaw_port);
            my $version = extrahiere_version($banner_info->{banner}, $banner_info->{server_header});

            # GeoIP-Land bestimmen
            my $country = hole_land_fuer_ip($ip);

            # Hostname auflösen
            my $hostname = gethostbyaddr(inet_aton($ip), AF_INET) // "";

            # Fund vorbereiten
            my $fund = {
                ip           => $ip,
                port         => $openclaw_port,
                timestamp    => localtime->strftime('%Y-%m-%d %H:%M:%S'),
                quelle       => $quelle,
                version      => $version,
                land         => $country,
                status       => 'aktiv',
                banner       => $banner_info->{banner},
                http_status  => $banner_info->{http_status},
                server_header => $banner_info->{server_header},
                ssl          => $banner_info->{ssl},
                hostname     => $hostname,
                scan_dauer   => $banner_info->{scan_dauer},
            };

            speichere_fund_csv($fund);
            $gefundene++;
        }

        # Pause für Rate Limiting
        select(undef, undef, undef, $pause_delay);
    }

    log_msg("INFO", "📊 Direktscan: $gefundene offene Ports gefunden von $total IPs");
    return $gefundene;
}

# ------------------------------------------------------------
# FUNKTION 8: Zufällige IPs generieren (für Tests)
# ------------------------------------------------------------
sub generiere_zufalls_ips {
    my ($anzahl) = @_;

    my @ips;
    for (1..$anzahl) {
        my $ip = int(rand(256)) . "." . int(rand(256)) . "." . int(rand(256)) . "." . int(rand(256));
        push @ips, $ip;
    }

    return @ips;
}

# ------------------------------------------------------------
# FUNKTION 9: Statistik erstellen
# ------------------------------------------------------------
sub zeige_statistik {
    return unless @funde;

    log_msg("INFO", "\n📊 OpenClaw-Funde Statistik:");
    log_msg("INFO", "=============================");

    # Nach Ländern
    my %laender;
    my %versionen;
    my %quellen;

    foreach my $fund (@funde) {
        $laender{$fund->{land} // 'XX'}++;
        $versionen{$fund->{version} // 'unbekannt'}++;
        $quellen{$fund->{quelle} // 'unbekannt'}++;
    }

    log_msg("INFO", "Top 5 Länder:");
    foreach my $land (sort { $laender{$b} <=> $laender{$a} } keys %laender) {
        last if ++$land > 5;
        log_msg("INFO", sprintf("   %s: %d Instanzen (%.1f%%)",
            $land, $laender{$land}, $laender{$land}/@funde*100));
    }

    log_msg("INFO", "\nVersionen:");
    foreach my $ver (sort keys %versionen) {
        log_msg("INFO", sprintf("   %s: %d", $ver, $versionen{$ver}));
    }

    log_msg("INFO", "\nQuellen:");
    foreach my $q (sort keys %quellen) {
        log_msg("INFO", sprintf("   %s: %d", $q, $quellen{$q}));
    }

    # Gefährdete Instanzen (alte Versionen)
    my $alte_versionen = 0;
    foreach my $fund (@funde) {
        if ($fund->{version} =~ /^202[0-4]/) {  # Versionen 2020-2024
            $alte_versionen++;
        }
    }

    if ($alte_versionen > 0) {
        log_msg("WARNUNG", "\n⚠️  Potenziell verwundbare Instanzen (vor 2025): $alte_versionen");
    }

    # Export-Zusammenfassung
    log_msg("INFO", "\n📁 CSV-Datei: $csv_datei");
    log_msg("INFO", "   " . scalar(@funde) . " Funde gespeichert");
}

# ------------------------------------------------------------
# HAUPTTEIL
# ------------------------------------------------------------
print "\n" . "=" x 60 . "\n";
print "🕷️  OpenClaw-Such-Script v0.1\n";
print "   by Klaus Baumdick (stoerti) aka \"The jobless hacker\"\n";
print "   Nur für Bildungszwecke!\n";
print "=" x 60 . "\n\n";

# CSV initialisieren
initialisiere_csv($csv_datei);

# Log-Start
log_msg("INFO", "🕷️  OpenClaw Scanner gestartet");
log_msg("INFO", "   Scan-ID: " . localtime->strftime('%Y%m%d_%H%M%S'));
log_msg("INFO", "   Host: " . hostname());

# Option 1: Shodan-Suche
unless ($scan_only) {
    suche_mit_shodan($shodan_api_key);
}

# Option 2: IPs aus Datei laden und scannen
unless ($shodan_only) {
    my @ziel_ips;

    # Aus Datei laden
    if (-e $ip_liste_datei) {
        push @ziel_ips, lade_ip_liste_aus_datei($ip_liste_datei);
    }

    # Manuelle Eingabe
    print "\n📝 Möchtest du IPs manuell eingeben? (ja/nein): ";
    my $antwort = <STDIN>;
    chomp $antwort;

    if ($antwort =~ /^j/i) {
        print "Bitte IPs eingeben (eine pro Zeile, STRG+D zum Beenden):\n";
        while (my $ip = <STDIN>) {
            chomp $ip;
            $ip =~ s/^\s+|\s+$//g;
            next unless $ip;
            push @ziel_ips, $ip;
        }
    }

    # Zufällige IPs für Testzwecke (nur wenn keine anderen Quellen)
    unless (@ziel_ips) {
        print "\n🎲 Keine IPs gefunden. Zufällige Test-IPs generieren? (ja/nein): ";
        $antwort = <STDIN>;
        chomp $antwort;

        if ($antwort =~ /^j/i) {
            push @ziel_ips, generiere_zufalls_ips(100000);
            log_msg("INFO", "🎲 100000 zufällige Test-IPs generiert");
        } else {
            log_msg("WARNUNG", "⚠️  Keine IPs zum Scannen vorhanden.");
            exit;
        }
    }

    # IPs scannen
    if (@ziel_ips) {
        log_msg("INFO", "📋 Insgesamt " . scalar(@ziel_ips) . " IPs zum Scannen");
        scanne_ip_liste(\@ziel_ips, 'direct_scan');
    }
}

# Statistik anzeigen
zeige_statistik();

# Scan-Dauer berechnen
my $scan_ende = localtime;
my $dauer = $scan_ende - $scan_start;
log_msg("INFO", "\n✅ Scan abgeschlossen in ${dauer} Sekunden");
log_msg("INFO", "   Ergebnisse in $csv_datei gespeichert");
log_msg("INFO", "   Log in $log_datei");

# Aufräumen
log_msg("INFO", "👋 Bis zum nächsten Mal!");
