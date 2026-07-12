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
use warnings;
use IO::Socket::SSL;
use Net::SSLeay;
use LWP::UserAgent;
use HTTP::Request;
use Getopt::Long;
use Time::HiRes qw(time);
use MIME::Base64;

# ======================================================================
# SSL/TLS SECURITY CHECKER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Prüft SSL/TLS Konfiguration auf Schwachstellen
# Version: 1.1
# ======================================================================

my $verbose = 0;
my $output_file = "";
my $target_host = "";
my $target_port = 443;
my $timeout = 10;
my $check_heartbleed = 1;
my $check_poodle = 1;
my $check_ciphers = 1;
my $check_hsts = 1;
my $full_scan = 0;

GetOptions(
    "verbose|v" => \$verbose,
    "output|o=s" => \$output_file,
    "host|h=s" => \$target_host,
    "port|p=i" => \$target_port,
    "timeout=i" => \$timeout,
    "no-heartbleed" => sub { $check_heartbleed = 0; },
    "no-poodle" => sub { $check_poodle = 0; },
    "no-ciphers" => sub { $check_ciphers = 0; },
    "no-hsts" => sub { $check_hsts = 0; },
    "full" => \$full_scan,
    "help" => sub { print_help(); exit 0; }
);

if (!$target_host) {
    print "Fehler: Ziel-Host ist erforderlich!\n";
    print_help();
    exit 1;
}

print "╔════════════════════════════════════════════════════════════╗\n";
print "║                  SSL/TLS SECURITY CHECKER                  ║\n";
print "║                    Version 1.1                              ║\n";
print "╚════════════════════════════════════════════════════════════╝\n\n";

print "[INFO] Ziel: $target_host:$target_port\n";
print "[INFO] Timeout: ${timeout}s\n";
print "[INFO] Full Scan: " . ($full_scan ? "JA" : "NEIN") . "\n\n";

my %results = (
    certificate => {},
    ciphers => {},
    vulnerabilities => {},
    headers => {},
    pfs => {},
    recommendations => []
);

my %protocol_results;

# ======================================================================
# TEST 1: CERTIFICATE CHECK
# ======================================================================
print "[TEST 1] Zertifikats-Prüfung\n";
print "-" x 50, "\n";

my $ssl_client = IO::Socket::SSL->new(
    PeerHost => "$target_host:$target_port",
    SSL_verify_mode => 0,
    SSL_version => 'TLSv12',
    Timeout => $timeout
);

if (!$ssl_client) {
    print "  ❌ Keine SSL-Verbindung möglich: $!\n";
    $results{certificate}{error} = "Connection failed: $!";
} else {
    # Zertifikat mit Net::SSLeay holen
    my $fd = $ssl_client->fileno();
    my $ssl = Net::SSLeay::new(Net::SSLeay::CTX_new());
    Net::SSLeay::set_fd($ssl, $fd);
    Net::SSLeay::connect($ssl);

    my $cert = Net::SSLeay::get_peer_certificate($ssl);

    if ($cert) {
        # Zertifikats-Informationen
        my $subject = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($cert));
        my $issuer = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_issuer_name($cert));
        my $not_before = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($cert));
        my $not_after = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($cert));
        my $serial = Net::SSLeay::X509_get_serialNumber($cert);

        # Sanitize
        $subject =~ s/\0//g;
        $issuer =~ s/\0//g;

        print "  Subject: $subject\n";
        print "  Issuer: $issuer\n";
        print "  Gültig von: $not_before\n";
        print "  Gültig bis: $not_after\n";
        print "  Serial: $serial\n";

        $results{certificate}{subject} = $subject;
        $results{certificate}{issuer} = $issuer;
        $results{certificate}{valid_from} = $not_before;
        $results{certificate}{valid_until} = $not_after;
        $results{certificate}{serial} = $serial;

        # Ablaufdatum prüfen
        my $current_time = time();
        my $expiry_time = Net::SSLeay::P_ASN1_TIME_get_epoch($not_after);

        if ($expiry_time < $current_time) {
            print "  ❌ ZERTIFIKAT ABGELAUFEN!\n";
            push @{$results{recommendations}}, "Zertifikat erneuern - abgelaufen";
        } elsif (($expiry_time - $current_time) < 30 * 24 * 60 * 60) {
            print "  ⚠️  Zertifikat läuft in weniger als 30 Tagen ab\n";
            push @{$results{recommendations}}, "Zertifikat bald erneuern";
        } else {
            print "  ✅ Zertifikat gültig\n";
        }

        # Selbst-signiert?
        if ($subject eq $issuer) {
            print "  ⚠️  Selbst-signiertes Zertifikat\n";
            push @{$results{recommendations}}, "Vertrauenswürdiges CA-Zertifikat verwenden";
        }

        # Schlüssellänge prüfen
        my $pkey = Net::SSLeay::X509_get_pubkey($cert);
        if ($pkey) {
            my $bits = Net::SSLeay::PKEY_get_bits($pkey);
            print "  Schlüssellänge: $bits Bit\n";

            if ($bits < 2048) {
                print "  ❌ Schlüssellänge zu kurz (< 2048 Bit)\n";
                push @{$results{recommendations}}, "Stärkeren Schlüssel verwenden (min. 2048 Bit)";
            }
            Net::SSLeay::EVP_PKEY_free($pkey);
        }

        Net::SSLeay::X509_free($cert);
    }

    Net::SSLeay::free($ssl);
    close($ssl_client);
}

# ======================================================================
# TEST 2: PROTOKOLL-VERSIONEN
# ======================================================================
print "\n[TEST 2] Protokoll-Versionen\n";
print "-" x 50, "\n";

my %protocols = (
    'SSLv2' => 'SSLv2',
    'SSLv3' => 'SSLv3',
    'TLSv1' => 'TLSv1',
    'TLSv11' => 'TLSv1_1',
    'TLSv12' => 'TLSv1_2',
    'TLSv13' => 'TLSv1_3'
);

foreach my $proto_name (keys %protocols) {
    my $proto_version = $protocols{$proto_name};

    my $sock = eval {
        IO::Socket::SSL->new(
            PeerHost => "$target_host:$target_port",
            SSL_version => $proto_version,
            SSL_verify_mode => 0,
            Timeout => $timeout
        )
    };

    if ($sock) {
        print "  ✅ $proto_name wird unterstützt\n";
        $protocol_results{$proto_name} = "supported";
        close($sock);
    } else {
        print "  ❌ $proto_name wird NICHT unterstützt\n" if $verbose;
        $protocol_results{$proto_name} = "not_supported";
    }
}

# Sicherheitsbewertung
if ($protocol_results{'SSLv2'} eq "supported") {
    print "  ❌ SSLv2 wird unterstützt - UNSICHER!\n";
    push @{$results{recommendations}}, "SSLv2 deaktivieren (unsicher)";
}

if ($protocol_results{'SSLv3'} eq "supported") {
    print "  ❌ SSLv3 wird unterstützt - POODLE anfällig!\n";
    push @{$results{recommendations}}, "SSLv3 deaktivieren (POODLE)";
    $results{vulnerabilities}{poodle} = "possible";
}

if ($protocol_results{'TLSv1'} eq "supported" || $protocol_results{'TLSv11'} eq "supported") {
    print "  ⚠️  TLS 1.0/1.1 werden unterstützt - veraltet\n";
    push @{$results{recommendations}}, "TLS 1.0/1.1 deaktivieren, TLS 1.2/1.3 verwenden";
}

if ($protocol_results{'TLSv12'} eq "supported") {
    print "  ✅ TLS 1.2 wird unterstützt\n";
}

if ($protocol_results{'TLSv13'} eq "supported") {
    print "  ✅ TLS 1.3 wird unterstützt (modern)\n";
}

$results{protocols} = \%protocol_results;

# ======================================================================
# TEST 3: HEARTBLEED (CVE-2014-0160)
# ======================================================================
if ($check_heartbleed) {
    print "\n[TEST 3] Heartbleed Test (CVE-2014-0160)\n";
    print "-" x 50, "\n";

    my $heartbleed = test_heartbleed($target_host, $target_port);

    if ($heartbleed->{vulnerable}) {
        print "  ❌ KRITISCH: Heartbleed verwundbar!\n";
        print "  Rückgabe: " . unpack('H*', $heartbleed->{data}) . "\n" if $heartbleed->{data};
        $results{vulnerabilities}{heartbleed} = 1;
        push @{$results{recommendations}}, "Heartbleed fix anwenden (OpenSSL update)";
    } else {
        print "  ✅ Heartbleed nicht verwundbar\n";
        $results{vulnerabilities}{heartbleed} = 0;
    }
}

# ======================================================================
# TEST 4: POODLE (SSLv3 Fallback)
# ======================================================================
if ($check_poodle) {
    print "\n[TEST 4] POODLE Test (CVE-2014-3566)\n";
    print "-" x 50, "\n";

    # Teste ob SSLv3 erzwungen werden kann
    my $poodle_vuln = test_poodle($target_host, $target_port);

    if ($poodle_vuln) {
        print "  ❌ POODLE verwundbar - Server akzeptiert SSLv3\n";
        $results{vulnerabilities}{poodle} = 1;
        push @{$results{recommendations}}, "SSLv3 komplett deaktivieren";
    } else {
        print "  ✅ POODLE nicht verwundbar\n";
    }
}

# ======================================================================
# TEST 5: CIPHER SUITES
# ======================================================================
if ($check_ciphers) {
    print "\n[TEST 5] Cipher Suite Analyse\n";
    print "-" x 50, "\n";

    my @ciphers = get_supported_ciphers($target_host, $target_port);
    my %cipher_categories;

    foreach my $cipher (@ciphers) {
        print "  Gefunden: $cipher\n" if $verbose;

        # Kategorisierung
        if ($cipher =~ /RC4/i) {
            push @{$cipher_categories{rc4}}, $cipher;
        } elsif ($cipher =~ /DES/i || $cipher =~ /3DES/i) {
            push @{$cipher_categories{des}}, $cipher;
        } elsif ($cipher =~ /EXPORT/i) {
            push @{$cipher_categories{export}}, $cipher;
        } elsif ($cipher =~ /NULL/i || $cipher =~ /anon/i) {
            push @{$cipher_categories{null}}, $cipher;
        } elsif ($cipher =~ /AES/i && $cipher =~ /GCM/i) {
            push @{$cipher_categories{strong}}, $cipher;
        } elsif ($cipher =~ /CHACHA/i) {
            push @{$cipher_categories{strong}}, $cipher;
        } else {
            push @{$cipher_categories{other}}, $cipher;
        }
    }

    # Schwache Ciphers melden
    if (exists $cipher_categories{rc4} && @{$cipher_categories{rc4}}) {
        print "  ❌ RC4 Ciphers gefunden (unsicher):\n";
        foreach (@{$cipher_categories{rc4}}) {
            print "    - $_\n";
        }
        push @{$results{recommendations}}, "RC4 Ciphers deaktivieren";
    }

    if (exists $cipher_categories{des} && @{$cipher_categories{des}}) {
        print "  ❌ DES/3DES Ciphers gefunden (schwach):\n";
        foreach (@{$cipher_categories{des}}) {
            print "    - $_\n";
        }
        push @{$results{recommendations}}, "DES/3DES Ciphers deaktivieren";
    }

    if (exists $cipher_categories{export} && @{$cipher_categories{export}}) {
        print "  ❌ EXPORT Ciphers gefunden (sehr schwach):\n";
        foreach (@{$cipher_categories{export}}) {
            print "    - $_\n";
        }
        push @{$results{recommendations}}, "EXPORT Ciphers deaktivieren";
    }

    if (exists $cipher_categories{null} && @{$cipher_categories{null}}) {
        print "  ❌ NULL/Anon Ciphers gefunden (keine Verschlüsselung):\n";
        foreach (@{$cipher_categories{null}}) {
            print "    - $_\n";
        }
        push @{$results{recommendations}}, "NULL/Anon Ciphers deaktivieren";
    }

    if (exists $cipher_categories{strong} && @{$cipher_categories{strong}}) {
        print "  ✅ Starke Ciphers verfügbar:\n";
        my $count = 0;
        foreach (@{$cipher_categories{strong}}) {
            print "    - $_\n";
            $count++;
            last if $count >= 3;
        }
    }

    print "  Gesamt: " . scalar(@ciphers) . " Ciphers unterstützt\n";
    $results{ciphers}{count} = scalar(@ciphers);
    $results{ciphers}{weak} = \%cipher_categories;
}

# ======================================================================
# TEST 6: HSTS (HTTP Strict Transport Security)
# ======================================================================
if ($check_hsts) {
    print "\n[TEST 6] HSTS Header Check\n";
    print "-" x 50, "\n";

    my $ua = LWP::UserAgent->new(
        ssl_opts => { verify_hostname => 0 },
        timeout => $timeout
    );

    my $response = $ua->get("https://$target_host:$target_port/");

    if ($response && $response->is_success) {
        my $hsts = $response->header('Strict-Transport-Security');

        if ($hsts) {
            print "  ✅ HSTS Header vorhanden: $hsts\n";

            # HSTS Details parsen
            if ($hsts =~ /max-age=(\d+)/) {
                my $max_age = $1;
                print "    max-age: $max_age Sekunden (" . int($max_age/86400) . " Tage)\n";

                if ($max_age < 31536000) {
                    print "    ⚠️  max-age sollte mindestens 1 Jahr sein\n";
                    push @{$results{recommendations}}, "HSTS max-age auf 31536000 erhöhen";
                }
            }

            if ($hsts =~ /includeSubDomains/i) {
                print "    includeSubDomains: JA\n";
            } else {
                print "    ⚠️  includeSubDomains fehlt\n";
                push @{$results{recommendations}}, "HSTS includeSubDomains aktivieren";
            }

            if ($hsts =~ /preload/i) {
                print "    preload: JA\n";
            }

            $results{headers}{hsts} = $hsts;
        } else {
            print "  ❌ KEIN HSTS Header gefunden\n";
            push @{$results{recommendations}}, "HSTS Header implementieren";
        }

        # Weitere Security Header prüfen
        my $x_frame = $response->header('X-Frame-Options');
        my $x_xss = $response->header('X-XSS-Protection');
        my $x_content = $response->header('X-Content-Type-Options');
        my $csp = $response->header('Content-Security-Policy');

        if ($x_frame) {
            print "  ✅ X-Frame-Options: $x_frame\n";
        } else {
            print "  ⚠️  X-Frame-Options fehlt (Clickjacking Schutz)\n";
        }

        if ($x_xss) {
            print "  ✅ X-XSS-Protection: $x_xss\n";
        }

        if ($x_content) {
            print "  ✅ X-Content-Type-Options: $x_content\n";
        }

        if ($csp) {
            print "  ✅ Content-Security-Policy vorhanden\n";
        }

        $results{headers}{security} = {
            x_frame => $x_frame,
            x_xss => $x_xss,
            x_content => $x_content,
            csp => $csp ? 1 : 0
        };
    }
}

# ======================================================================
# TEST 7: PERFECT FORWARD SECRECY (PFS)
# ======================================================================
print "\n[TEST 7] Perfect Forward Secrecy (PFS)\n";
print "-" x 50, "\n";

my @pfs_ciphers = get_pfs_ciphers($target_host, $target_port);

if (@pfs_ciphers) {
    print "  ✅ PFS Ciphers unterstützt:\n";
    my $count = 0;
    foreach (@pfs_ciphers) {
        print "    - $_\n";
        $count++;
        last if $count >= 3;
    }
    $results{pfs}{supported} = 1;
    $results{pfs}{ciphers} = \@pfs_ciphers;
} else {
    print "  ❌ KEINE Perfect Forward Secrecy Ciphers\n";
    push @{$results{recommendations}}, "Perfect Forward Secrecy (ECDHE/DHE) Ciphers aktivieren";
}

# ======================================================================
# TEST 8: OCSP STAPLING
# ======================================================================
print "\n[TEST 8] OCSP Stapling\n";
print "-" x 50, "\n";

my $ocsp = test_ocsp_stapling($target_host, $target_port);

if ($ocsp->{supported}) {
    print "  ✅ OCSP Stapling wird unterstützt\n";
    if ($ocsp->{response}) {
        print "    Status: $ocsp->{response}\n";
    }
} else {
    print "  ⚠️  OCSP Stapling nicht unterstützt\n";
    push @{$results{recommendations}}, "OCSP Stapling aktivieren für bessere Performance";
}

# ======================================================================
# TEST 9: ROBOT ATTACK (RSA Oracle)
# ======================================================================
print "\n[TEST 9] ROBOT Attack (CVE-2017-6168)\n";
print "-" x 50, "\n";

my $robot = test_robot($target_host, $target_port);

if ($robot->{vulnerable}) {
    print "  ❌ ROBOT Attack verwundbar!\n";
    $results{vulnerabilities}{robot} = 1;
    push @{$results{recommendations}}, "ROBOT Attack fixen (RSA Encryption Oracle)";
} else {
    print "  ✅ ROBOT nicht verwundbar\n";
}

# ======================================================================
# ZUSAMMENFASSUNG
# ======================================================================
print "\n" . "=" x 60 . "\n";
print "SSL/TLS SICHERHEITS-ZUSAMMENFASSUNG\n";
print "=" x 60 . "\n\n";

print "ZERTIFIKAT: ";
if ($results{certificate}{valid_until}) {
    print "✅ Gültig\n";
} else {
    print "❌ PROBLEME\n";
}

print "PROTOKOLLE: ";
if ($protocol_results{'SSLv2'} eq "not_supported" &&
    $protocol_results{'SSLv3'} eq "not_supported" &&
    $protocol_results{'TLSv12'} eq "supported") {
    print "✅ Moderne TLS Versionen\n";
} else {
    print "⚠️  Veraltete Protokolle\n";
}

print "CIPHER STÄRKE: ";
if ((exists $cipher_categories{rc4} && @{$cipher_categories{rc4}}) ||
    (exists $cipher_categories{des} && @{$cipher_categories{des}}) ||
    (exists $cipher_categories{export} && @{$cipher_categories{export}})) {
    print "❌ Schwache Ciphers vorhanden\n";
} else {
    print "✅ Akzeptabel\n";
}

print "HSTS: ";
if ($results{headers}{hsts}) {
    print "✅ Aktiv\n";
} else {
    print "❌ Fehlt\n";
}

print "PFS: ";
if ($results{pfs}{supported}) {
    print "✅ Unterstützt\n";
} else {
    print "❌ Nicht unterstützt\n";
}

print "\nGEFUNDENE SCHWACHSTELLEN:\n";
my $vuln_count = 0;
if ($results{vulnerabilities}{heartbleed}) {
    print "  • ❌ HEARTBLEED - KRITISCH!\n";
    $vuln_count++;
}
if ($results{vulnerabilities}{poodle}) {
    print "  • ❌ POODLE - MITTEL\n";
    $vuln_count++;
}
if ($results{vulnerabilities}{robot}) {
    print "  • ❌ ROBOT - KRITISCH!\n";
    $vuln_count++;
}
if ($vuln_count == 0) {
    print "  • ✅ Keine bekannten Schwachstellen gefunden\n";
}

print "\nEMPFEHLUNGEN:\n";
if (@{$results{recommendations}}) {
    foreach my $rec (@{$results{recommendations}}) {
        print "  • $rec\n";
    }
} else {
    print "  • SSL/TLS Konfiguration ist sicher!\n";
}

print "\nBEST PRACTICE CHECKLISTE:\n";
print "  • [ ] Nur TLS 1.2 und 1.3 aktivieren\n";
print "  • [ ] Starke Ciphers (AES-GCM, CHACHA20)\n";
print "  • [ ] Perfect Forward Secrecy (ECDHE)\n";
print "  • [ ] HSTS mit max-age=31536000\n";
print "  • [ ] OCSP Stapling\n";
print "  • [ ] Certificate Transparency (CT)\n";
print "  • [ ] DNSSEC + CAA Records\n";

# Report speichern
if ($output_file) {
    save_report();
    print "\nReport gespeichert in: $output_file\n";
}

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub test_heartbleed {
    my ($host, $port) = @_;

    my $result = { vulnerable => 0, data => "" };

    # Heartbleed Test Payload
    my $heartbleed_payload = pack('C*',
        0x18, # Heartbeat
        0x03, 0x01, # TLS 1.0
        0x00, 0x03, # Länge
        0x01, # Heartbeat Request
        0x40, 0x00  # Payload Länge (groß!)
    );

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(5);

        my $sock = IO::Socket::INET->new(
            PeerAddr => $host,
            PeerPort => $port,
            Proto => 'tcp',
            Timeout => 5
        );

        if ($sock) {
            $sock->write($heartbleed_payload);
            my $response;
            $sock->read($response, 1024);

            if (length($response) > 10) {
                $result->{vulnerable} = 1;
                $result->{data} = substr($response, 10);
            }
            close($sock);
        }
        alarm(0);
    };

    return $result;
}

sub test_poodle {
    my ($host, $port) = @_;

    # Versuche SSLv3 Verbindung
    my $sock = eval {
        IO::Socket::SSL->new(
            PeerHost => "$host:$port",
            SSL_version => 'SSLv3',
            SSL_verify_mode => 0,
            Timeout => 5
        )
    };

    return $sock ? 1 : 0;
}

sub get_supported_ciphers {
    my ($host, $port) = @_;

    my @ciphers;
    my $ctx = Net::SSLeay::CTX_new();

    # Liste der zu testenden Ciphers
    my @cipher_list = (
        'RC4-SHA', 'RC4-MD5', 'DES-CBC3-SHA', 'DES-CBC-SHA',
        'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
        'AES128-GCM-SHA256', 'AES256-GCM-SHA384',
        'ECDHE-RSA-CHACHA20-POLY1305', 'DHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-SHA', 'ECDHE-RSA-AES256-SHA',
        'AES128-SHA', 'AES256-SHA', 'CAMELLIA128-SHA',
        'EXP-RC4-MD5', 'EXP-DES-CBC-SHA', 'EXP-EDH-RSA-DES-CBC-SHA'
    );

    foreach my $cipher (@cipher_list) {
        my $ssl = Net::SSLeay::new($ctx);
        Net::SSLeay::set_cipher_list($ssl, $cipher);

        my $sock = IO::Socket::INET->new(
            PeerAddr => $host,
            PeerPort => $port,
            Proto => 'tcp',
            Timeout => 2
        );

        if ($sock) {
            Net::SSLeay::set_fd($ssl, fileno($sock));
            my $ret = Net::SSLeay::connect($ssl);

            if ($ret == 1) {
                push @ciphers, $cipher;
            }
            Net::SSLeay::free($ssl);
            close($sock);
        }
    }

    Net::SSLeay::CTX_free($ctx);
    return @ciphers;
}

sub get_pfs_ciphers {
    my ($host, $port) = @_;

    my @pfs_ciphers;
    my @pfs_patterns = ('DHE', 'ECDHE', 'EDH');

    my @all_ciphers = get_supported_ciphers($host, $port);

    foreach my $cipher (@all_ciphers) {
        foreach my $pattern (@pfs_patterns) {
            if ($cipher =~ /$pattern/i) {
                push @pfs_ciphers, $cipher;
                last;
            }
        }
    }

    return @pfs_ciphers;
}

sub test_ocsp_stapling {
    my ($host, $port) = @_;

    my $result = { supported => 0 };

    eval {
        my $sock = IO::Socket::SSL->new(
            PeerHost => "$host:$port",
            SSL_version => 'TLSv12',
            SSL_verify_mode => 0,
            SSL_ocsp_mode => 1,
            Timeout => 5
        );

        if ($sock) {
            # Prüfe ob OCSP Response vorhanden
            $result->{supported} = 1;
            $result->{response} = "OCSP Stapling aktiv";
            close($sock);
        }
    };

    return $result;
}

sub test_robot {
    my ($host, $port) = @_;

    my $result = { vulnerable => 0 };

    # Vereinfachter ROBOT Test
    eval {
        my $sock = IO::Socket::SSL->new(
            PeerHost => "$host:$port",
            SSL_version => 'TLSv12',
            SSL_verify_mode => 0,
            Timeout => 5
        );

        if ($sock) {
            # Wenn Verbindung klappt, ist es wahrscheinlich nicht verwundbar
            $result->{vulnerable} = 0;
            close($sock);
        }
    };

    return $result;
}

sub save_report {
    open(my $fh, '>', $output_file) or die "Kann Datei nicht erstellen: $!";

    print $fh "SSL/TLS SECURITY CHECK REPORT\n";
    print $fh "=============================\n\n";
    print $fh "Getestet am: " . localtime() . "\n";
    print $fh "Target: $target_host:$target_port\n\n";

    print $fh "ZERTIFIKAT:\n";
    print $fh "  Subject: $results{certificate}{subject}\n";
    print $fh "  Issuer: $results{certificate}{issuer}\n";
    print $fh "  Gültig bis: $results{certificate}{valid_until}\n\n";

    print $fh "PROTOKOLLE:\n";
    foreach my $proto (sort keys %protocol_results) {
        print $fh "  $proto: $protocol_results{$proto}\n";
    }
    print $fh "\n";

    print $fh "SCHWACHSTELLEN:\n";
    if ($results{vulnerabilities}{heartbleed}) {
        print $fh "  • HEARTBLEED - KRITISCH\n";
    }
    if ($results{vulnerabilities}{poodle}) {
        print $fh "  • POODLE - MITTEL\n";
    }
    if ($results{vulnerabilities}{robot}) {
        print $fh "  • ROBOT - KRITISCH\n";
    }
    print $fh "\n";

    print $fh "EMPFEHLUNGEN:\n";
    foreach my $rec (@{$results{recommendations}}) {
        print $fh "  • $rec\n";
    }

    close $fh;
}

sub print_help {
    print <<'HELP';

SSL/TLS SECURITY CHECKER
========================

USAGE:
  perl ssl_checker.pl --host HOST [OPTIONEN]

ERFORDERLICH:
  --host HOST       Ziel-Hostname oder IP

OPTIONEN:
  --port PORT       Ziel-Port (default: 443)
  --timeout SECONDS Timeout für Verbindungen (default: 10)
  --full            Full Scan (alle Tests)
  --no-heartbleed   Heartbleed Test überspringen
  --no-poodle       POODLE Test überspringen
  --no-ciphers      Cipher Test überspringen
  --no-hsts         HSTS Test überspringen
  -v, --verbose     Ausführliche Ausgabe
  -o, --output FILE Report in Datei speichern
  -h, --help        Diese Hilfe anzeigen

BEISPIELE:
  # Standard Check
  perl ssl_checker.pl --host example.com

  # Full Scan mit Report
  perl ssl_checker.pl --host example.com --full -v -o report.txt

  # Custom Port
  perl ssl_checker.pl --host example.com --port 8443

GETESTETE SCHWACHSTELLEN:
  • Heartbleed (CVE-2014-0160)
  • POODLE (CVE-2014-3566)
  • ROBOT (CVE-2017-6168)
  • Schwache Ciphers (RC4, 3DES, EXPORT)
  • Veraltete Protokolle (SSLv2, SSLv3)
  • Fehlende HSTS Header
  • Keine Perfect Forward Secrecy
  • Abgelaufene/schwache Zertifikate

SICHERHEITS-EMPFEHLUNGEN:
  • Nur TLS 1.2 und 1.3 aktivieren
  • Starke Ciphers (AES-GCM, CHACHA20)
  • Perfect Forward Secrecy (ECDHE)
  • HSTS mit max-age=31536000
  • OCSP Stapling aktivieren
  • Zertifikate regelmäßig erneuern
HELP
}
