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
use List::Util qw(min max);

# ======================================================================
# WORDPRESS USER ENUMERATION TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet ob WordPress-Benutzernamen ausgelesen werden können
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet verschiedene Enumeration-Methoden:
#   • /?author=N
#   • /wp-json/wp/v2/users
#   • /wp-content/themes/...
#   • Login-Fehlermeldungen
#   • RSS-Feeds
#   • Kommentare
#   • Sitemaps
# ======================================================================

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
    max_users    => 20,           # Maximale Anzahl zu findender User
    timeout      => 10,
    verbose      => 0,
    quiet        => 0,
    output_json  => '',
    user_agent   => 'Mozilla/5.0 (WordPress User Enum Tester)',
    delay        => 0.5,          # Pause zwischen Requests (Sekunden)
    follow_redirects => 0,
    cookie       => '',
    auth_user    => '',
    auth_pass    => '',
    check_all    => 0,             # Alle Methoden testen (auch langsame)
    start_id     => 1,             # Start-Author-ID
    end_id       => 20,            # End-Author-ID
    wordlist     => '',            # Datei mit Benutzernamen zum Testen
    threshold    => 0.5,           # Schwellwert für Timing-Analyse
);

# ======================================================================
# KOMMANDOZEILENOPTIONEN
# ======================================================================
GetOptions(
    'url=s'           => \$config{target_url},
    'max-users=i'     => \$config{max_users},
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
    'check-all'       => \$config{check_all},
    'start-id=i'      => \$config{start_id},
    'end-id=i'        => \$config{end_id},
    'wordlist=s'      => \$config{wordlist},
    'threshold=f'     => \$config{threshold},
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
my @found_users = ();
my %methods_results = ();

show_banner();
print_info("Ziel: $config{target_url}");
print_info("Max Users: $config{max_users}");
print_info("Timeout: $config{timeout} Sekunden");

# User-Agent erstellen
my $ua = create_user_agent();

# ======================================================================
# 1. PRÜFEN OB WORDPRESS ERKANNT WURDE
# ======================================================================
print_section("WORDPRESS ERKENNUNG");

my $is_wordpress = check_wordpress($ua);
if (!$is_wordpress) {
    print_warning("Kein WordPress erkannt - trotzdem testen?");
    if (!$config{quiet}) {
        print "Fortfahren? (j/N): ";
        my $answer = <STDIN>;
        chomp $answer;
        if ($answer !~ /^j/i) {
            print_info("Abgebrochen");
            exit 0;
        }
    }
} else {
    print_success("WordPress erkannt");
}

# ======================================================================
# 2. METHODE 1: AUTHOR ARCHIVE (?author=N)
# ======================================================================
print_section("METHODE 1: AUTHOR ARCHIVE (?author=N)");

my @author_users = test_author_archive($ua);
foreach my $user (@author_users) {
    add_user($user, 'author_archive');
}

# ======================================================================
# 3. METHODE 2: REST API (/wp-json/wp/v2/users)
# ======================================================================
if ($config{check_all} || @found_users < $config{max_users}) {
    print_section("METHODE 2: REST API ENDPUNKTE");

    my @rest_users = test_rest_api($ua);
    foreach my $user (@rest_users) {
        add_user($user, 'rest_api');
    }
}

# ======================================================================
# 4. METHODE 3: LOGIN-FEHLERMELDUNGEN
# ======================================================================
if ($config{check_all} || @found_users < $config{max_users}) {
    print_section("METHODE 3: LOGIN-FEHLERMELDUNGEN");

    my @login_users = test_login_feedback($ua);
    foreach my $user (@login_users) {
        add_user($user, 'login_feedback');
    }
}

# ======================================================================
# 5. METHODE 4: RSS FEEDS
# ======================================================================
if ($config{check_all} || @found_users < $config{max_users}) {
    print_section("METHODE 4: RSS FEEDS");

    my @rss_users = test_rss_feeds($ua);
    foreach my $user (@rss_users) {
        add_user($user, 'rss_feed');
    }
}

# ======================================================================
# 6. METHODE 5: KOMMENTARE
# ======================================================================
if ($config{check_all} || @found_users < $config{max_users}) {
    print_section("METHODE 5: KOMMENTARE");

    my @comment_users = test_comments($ua);
    foreach my $user (@comment_users) {
        add_user($user, 'comments');
    }
}

# ======================================================================
# 7. METHODE 6: SITEMAP
# ======================================================================
if ($config{check_all} || @found_users < $config{max_users}) {
    print_section("METHODE 6: SITEMAP");

    my @sitemap_users = test_sitemap($ua);
    foreach my $user (@sitemap_users) {
        add_user($user, 'sitemap');
    }
}

# ======================================================================
# 8. METHODE 7: WORDLIST/TIMING (falls angegeben)
# ======================================================================
if ($config{wordlist} && @found_users < $config{max_users}) {
    print_section("METHODE 7: WORDLIST + TIMING-ANALYSE");

    my @wordlist_users = test_wordlist_timing($ua);
    foreach my $user (@wordlist_users) {
        add_user($user, 'wordlist_timing');
    }
}

# ======================================================================
# 9. METHODE 8: OEMBED
# ======================================================================
if ($config{check_all} || @found_users < $config{max_users}) {
    print_section("METHODE 8: OEMBED ENDPUNKTE");

    my @oembed_users = test_oembed($ua);
    foreach my $user (@oembed_users) {
        add_user($user, 'oembed');
    }
}

# ======================================================================
# 10. ERGEBNISSE ANZEIGEN
# ======================================================================
print_section("ERGEBNISSE");

show_results();

# ======================================================================
# 11. JSON-OUTPUT
# ======================================================================
if ($config{output_json}) {
    save_json_output();
}

# ======================================================================
# 12. EMPFEHLUNGEN
# ======================================================================
print_recommendations();

# ======================================================================
# ABSCHLUSS
# ======================================================================
my $total_time = time() - $start_time;
print_info(sprintf("Gesamtzeit: %.2f Sekunden", $total_time));
print_info("Gefundene Benutzer: " . scalar(@found_users));

exit(scalar(@found_users) > 0 ? 1 : 0);

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
    if ($config{cookie}) {
        push @{$ua->default_headers}, ('Cookie' => $config{cookie});
    }

    return $ua;
}

sub check_wordpress {
    my ($ua) = @_;

    my $resp = $ua->get($config{target_url});

    if ($resp->is_success) {
        my $content = $resp->content;

        # WordPress-Indikatoren
        my @indicators = (
            'wordpress',
            'wp-content',
            'wp-includes',
            'wp-json',
            'xmlrpc.php',
            'pingback',
            'WordPress',
        );

        foreach my $ind (@indicators) {
            if ($content =~ /$ind/i) {
                print_info("Indikator gefunden: $ind");
                return 1;
            }
        }
    }

    return 0;
}

sub test_author_archive {
    my ($ua) = @_;
    my @users = ();

    print_info("Teste Author-IDs $config{start_id} bis $config{end_id}");

    for (my $id = $config{start_id}; $id <= $config{end_id}; $id++) {
        last if @users >= $config{max_users};

        my $url = "$config{target_url}/?author=$id";
        print "  Teste ID $id...\r" if $config{verbose};

        my $resp = $ua->get($url);

        # Redirect zu /author/name/?
        if ($resp->code == 301 || $resp->code == 302) {
            my $location = $resp->header('Location');
            if ($location && $location =~ /\/author\/([^\/]+)/) {
                my $username = $1;
                print "    → ID $id: $username\n" if $config{verbose};
                push @users, {
                    id => $id,
                    username => $username,
                    url => $location,
                };
            }
        }

        # Auch 200 OK prüfen (manche Themes zeigen direkt Author-Seite)
        elsif ($resp->code == 200) {
            my $content = $resp->content;
            if ($content =~ /<title>(?:.*?)Author:?\s*(.*?)<\/title>/i) {
                my $username = $1;
                print "    → ID $id: $username\n" if $config{verbose};
                push @users, {
                    id => $id,
                    username => $username,
                    url => $url,
                };
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Author-Archive: " . scalar(@users) . " Benutzer gefunden");
    return @users;
}

sub test_rest_api {
    my ($ua) = @_;
    my @users = ();

    # Verschiedene REST-API Endpunkte testen
    my @endpoints = (
        "$config{target_url}/wp-json/wp/v2/users",
        "$config{target_url}/wp-json/wp/v2/users/?per_page=100",
        "$config{target_url}/?rest_route=/wp/v2/users",
        "$config{target_url}/wp-json/wp/v2/users/?context=embed",
    );

    foreach my $endpoint (@endpoints) {
        last if @users >= $config{max_users};

        print_info("Teste REST-API: $endpoint");

        my $resp = $ua->get($endpoint);

        if ($resp->is_success) {
            my $content = $resp->content;

            # JSON parsen
            eval {
                my $data = decode_json($content);

                if (ref $data eq 'ARRAY') {
                    foreach my $user (@$data) {
                        last if @users >= $config{max_users};

                        my $username = $user->{slug} || $user->{name} || '';
                        my $id = $user->{id} || 0;

                        if ($username) {
                            print "    → Gefunden: $username (ID: $id)\n" if $config{verbose};
                            push @users, {
                                id => $id,
                                username => $username,
                                method => 'rest_api',
                                data => $user,
                            };
                        }
                    }
                }
            };

            if ($@) {
                print_warning("Fehler beim JSON-Parsing: $@") if $config{verbose};
            }
        }
        elsif ($resp->code == 401 || $resp->code == 403) {
            print_info("REST-API geschützt (HTTP $resp->code)");
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("REST-API: " . scalar(@users) . " Benutzer gefunden");
    return @users;
}

sub test_login_feedback {
    my ($ua) = @_;
    my @users = ();

    # Test-Usernamen für Login-Feedback
    my @test_users = ('admin', 'administrator', 'test', 'user', 'root');

    # Wenn wir bereits Users haben, diese auch testen
    if (@found_users) {
        push @test_users, map { $_->{username} } @found_users;
    }

    my %seen;
    foreach my $user (@test_users) {
        last if @users >= $config{max_users};
        next if $seen{$user}++;

        print "  Teste Benutzer '$user'...\r" if $config{verbose};

        # Login-URL finden
        my $login_url = find_login_url($ua);

        if ($login_url) {
            # Test mit falschem Passwort
            my $resp = $ua->post($login_url,
                'Content_Type' => 'application/x-www-form-urlencoded',
                'Content' => {
                    'log' => $user,
                    'pwd' => 'falsches_passwort_' . rand(),
                    'wp-submit' => 'Log In',
                    'testcookie' => '1'
                }
            );

            my $content = $resp->content;

            # WordPress unterscheidet oft in Fehlermeldungen
            if ($content =~ /<div[^>]*id="login_error"[^>]*>/) {
                my $error = $1 if $content =~ /<div[^>]*id="login_error"[^>]*>(.*?)<\/div>/s;

                if ($error) {
                    # "Ungültiger Benutzername" vs "Falsches Passwort"
                    if ($error !~ /(?:ungültig|invalid|unbekannt).*?(?:benutzername|username)/i) {
                        # Keine Unterscheidung? Dann könnte User existieren
                        print "    → Benutzer '$user' existiert wahrscheinlich\n" if $config{verbose};
                        push @users, {
                            username => $user,
                            method => 'login_feedback',
                            confidence => 'medium',
                        };
                    }
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Login-Feedback: " . scalar(@users) . " Benutzer gefunden");
    return @users;
}

sub test_rss_feeds {
    my ($ua) = @_;
    my @users = ();

    my @feeds = (
        "$config{target_url}/feed",
        "$config{target_url}/rss",
        "$config{target_url}/rss2",
        "$config{target_url}/feed/rss",
        "$config{target_url}/comments/feed",
    );

    foreach my $feed (@feeds) {
        last if @users >= $config{max_users};

        print_info("Teste Feed: $feed");

        my $resp = $ua->get($feed);

        if ($resp->is_success) {
            my $content = $resp->content;

            # Suche nach <dc:creator> oder <author>
            while ($content =~ /<(?:dc:creator|author)[^>]*>(.*?)<\//gi) {
                last if @users >= $config{max_users};

                my $username = $1;
                $username =~ s/^\s+|\s+$//g;

                if ($username && $username !~ /^wp_/i) {
                    print "    → Gefunden: $username\n" if $config{verbose};
                    push @users, {
                        username => $username,
                        method => 'rss_feed',
                        source => $feed,
                    };
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("RSS-Feeds: " . scalar(@users) . " Benutzer gefunden");
    return @users;
}

sub test_comments {
    my ($ua) = @_;
    my @users = ();

    # Versuche die letzten Beiträge zu finden
    my $resp = $ua->get($config{target_url});

    if ($resp->is_success) {
        my $content = $resp->content;

        # Suche nach Kommentar-Autoren
        while ($content =~ /<span[^>]*class="[^"]*comment-author[^"]*"[^>]*>(.*?)<\/span>/gi) {
            last if @users >= $config{max_users};

            my $author = $1;
            if ($author =~ /<a[^>]*>(.*?)<\/a>/) {
                my $username = $1;
                $username =~ s/^\s+|\s+$//g;

                if ($username) {
                    print "    → Kommentar-Autor: $username\n" if $config{verbose};
                    push @users, {
                        username => $username,
                        method => 'comments',
                        type => 'display_name',
                    };
                }
            }
        }
    }

    print_success("Kommentare: " . scalar(@users) . " Benutzer gefunden");
    return @users;
}

sub test_sitemap {
    my ($ua) = @_;
    my @users = ();

    my @sitemaps = (
        "$config{target_url}/sitemap.xml",
        "$config{target_url}/wp-sitemap.xml",
        "$config{target_url}/sitemap_index.xml",
    );

    foreach my $sitemap (@sitemaps) {
        last if @users >= $config{max_users};

        print_info("Teste Sitemap: $sitemap");

        my $resp = $ua->get($sitemap);

        if ($resp->is_success) {
            my $content = $resp->content;

            # Suche nach Author-Pfaden in Sitemap
            while ($content =~ /<loc>(.*?author[^<]*)<\/loc>/gi) {
                last if @users >= $config{max_users};

                my $url = $1;
                if ($url =~ /\/author\/([^\/]+)/) {
                    my $username = $1;
                    print "    → Author in Sitemap: $username\n" if $config{verbose};
                    push @users, {
                        username => $username,
                        method => 'sitemap',
                        url => $url,
                    };
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("Sitemap: " . scalar(@users) . " Benutzer gefunden");
    return @users;
}

sub test_oembed {
    my ($ua) = @_;
    my @users = ();

    # oEmbed-Endpunkte testen
    my @oembed_endpoints = (
        "$config{target_url}/wp-json/oembed/1.0/embed",
        "$config{target_url}/?rest_route=/oembed/1.0/embed",
    );

    # Wenn wir bereits Posts haben, teste sie
    my $resp = $ua->get($config{target_url});
    if ($resp->is_success) {
        my $content = $resp->content;
        my @post_urls = ($content =~ /<a[^>]*href="([^"]*)"[^>]*>/g);

        foreach my $post_url (@post_urls) {
            last if @users >= $config{max_users};
            next if $post_url !~ /$config{target_url}/;

            foreach my $endpoint (@oembed_endpoints) {
                my $oembed_url = "$endpoint?url=" . uri_escape($post_url);

                my $oembed_resp = $ua->get($oembed_url);

                if ($oembed_resp->is_success) {
                    eval {
                        my $data = decode_json($oembed_resp->content);
                        if ($data->{author_name}) {
                            my $username = $data->{author_name};
                            print "    → oEmbed Author: $username\n" if $config{verbose};
                            push @users, {
                                username => $username,
                                method => 'oembed',
                                data => $data,
                            };
                        }
                    };
                }

                sleep($config{delay}) if $config{delay} > 0;
                last if @users >= $config{max_users};
            }
        }
    }

    print_success("oEmbed: " . scalar(@users) . " Benutzer gefunden");
    return @users;
}

sub test_wordlist_timing {
    my ($ua) = @_;
    my @users = ();

    # Wordlist einlesen
    open(my $fh, '<', $config{wordlist}) or do {
        print_error("Kann Wordlist nicht öffnen: $!");
        return ();
    };

    my @usernames = <$fh>;
    chomp @usernames;
    close($fh);

    print_info("Teste " . scalar(@usernames) . " Benutzernamen aus Wordlist");

    # Login-URL finden
    my $login_url = find_login_url($ua);

    if (!$login_url) {
        print_warning("Keine Login-URL gefunden");
        return ();
    }

    # Baseline für nicht-existierende User
    my $baseline = measure_login_time($ua, $login_url, 'sicherheitstest_' . rand());
    print_info("Baseline-Zeit: " . sprintf("%.4f", $baseline) . "s");

    my $count = 0;
    foreach my $username (@usernames) {
        last if @users >= $config{max_users};
        $count++;

        print "  Teste $count/" . scalar(@usernames) . ": $username\r" if $config{verbose};

        my $duration = measure_login_time($ua, $login_url, $username);

        # Wenn Antwortzeit deutlich länger, existiert User wahrscheinlich
        if ($duration > $baseline * (1 + $config{threshold})) {
            print "\n    → Potenzieller User: $username (Zeit: " . sprintf("%.4f", $duration) . "s)\n" if $config{verbose};
            push @users, {
                username => $username,
                method => 'timing',
                duration => $duration,
                baseline => $baseline,
                ratio => $duration / $baseline,
            };
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Wordlist-Timing: " . scalar(@users) . " potenzielle User gefunden");
    return @users;
}

sub measure_login_time {
    my ($ua, $login_url, $username) = @_;

    my $start = time();
    my $resp = $ua->post($login_url,
        'Content_Type' => 'application/x-www-form-urlencoded',
        'Content' => {
            'log' => $username,
            'pwd' => 'falsches_passwort_' . rand(),
            'wp-submit' => 'Log In',
            'testcookie' => '1'
        }
    );
    my $duration = time() - $start;

    return $duration;
}

sub find_login_url {
    my ($ua) = @_;

    my @possible_urls = (
        "$config{target_url}/wp-login.php",
        "$config{target_url}/login",
        "$config{target_url}/wp-admin",
        "$config{target_url}/admin",
    );

    foreach my $url (@possible_urls) {
        my $resp = $ua->get($url);
        if ($resp->is_success || $resp->code == 200) {
            return $url;
        }
    }

    return undef;
}

sub add_user {
    my ($user, $method) = @_;

    # Prüfen ob User schon existiert
    my $exists = grep { $_->{username} eq $user->{username} } @found_users;

    if (!$exists) {
        $user->{found_by} = [] unless $user->{found_by};
        push @{$user->{found_by}}, $method;
        push @found_users, $user;

        print_success("NEU: $user->{username} (via $method)");
    } else {
        # Methode zu existierendem User hinzufügen
        foreach my $existing (@found_users) {
            if ($existing->{username} eq $user->{username}) {
                push @{$existing->{found_by}}, $method;
                print_info("Bereits bekannt: $user->{username} (auch via $method)");
                last;
            }
        }
    }
}

sub show_results {
    print "\n" . "=" x 60 . "\n";
    print "GEFUNDENE BENUTZER (" . scalar(@found_users) . "):\n";
    print "=" x 60 . "\n";

    if (@found_users == 0) {
        print "❌ Keine Benutzer gefunden\n";
        print "Die Seite scheint gegen User Enumeration geschützt.\n";
    } else {
        foreach my $user (sort { $a->{username} cmp $b->{username} } @found_users) {
            print "  • $GREEN$user->{username}$RESET\n";

            # Methoden anzeigen
            if ($user->{found_by} && @{$user->{found_by}} > 0) {
                my %method_names = (
                    'author_archive' => 'Author Archive',
                    'rest_api' => 'REST API',
                    'login_feedback' => 'Login Feedback',
                    'rss_feed' => 'RSS Feed',
                    'comments' => 'Kommentare',
                    'sitemap' => 'Sitemap',
                    'oembed' => 'oEmbed',
                    'wordlist_timing' => 'Timing-Analyse',
                );

                my @methods = map { $method_names{$_} || $_ } @{$user->{found_by}};
                print "    Gefunden via: " . join(', ', @methods) . "\n";
            }

            # ID anzeigen falls vorhanden
            if ($user->{id}) {
                print "    ID: $user->{id}\n";
            }
        }
    }

    # Zusammenfassung nach Methode
    print "\n" . "-" x 40 . "\n";
    print "ERFOLG NACH METHODE:\n";

    my %method_count;
    foreach my $user (@found_users) {
        foreach my $method (@{$user->{found_by}}) {
            $method_count{$method}++;
        }
    }

    foreach my $method (sort keys %method_count) {
        my $count = $method_count{$method};
        my $percentage = int($count / @found_users * 100);
        print "  • $method: $count Users ($percentage%)\n";
    }
}

sub save_json_output {
    my $output = {
        tool => "WordPress User Enumeration Tester",
        version => "1.0",
        timestamp => scalar(localtime()),
        unix_time => time(),
        target => $config{target_url},
        config => \%config,
        results => {
            total_users => scalar(@found_users),
            users => \@found_users,
            methods => \%methods_results,
        },
        vulnerability_found => scalar(@found_users) > 0 ? JSON::PP::true : JSON::PP::false,
        severity => scalar(@found_users) > 0 ? "MEDIUM" : "NONE",
        total_time => time() - $start_time,
        recommendations => get_recommendations_array(),
    };

    my $json = JSON::PP->new->pretty->encode($output);

    open(my $fh, '>', $config{output_json}) or die "Kann Datei nicht öffnen: $!";
    print $fh $json;
    close($fh);

    print_success("Ergebnisse gespeichert: $config{output_json}");
}

sub get_recommendations_array {
    my @recs = (
        "Author Archive deaktivieren: Keine ?author=N Weiterleitung erlauben",
        "REST-API Zugriff einschränken: 'rest_authentication_errors' Filter nutzen",
        "Login-Fehler uniform gestalten: 'login_errors' Filter verwenden",
        "oEmbed-Endpunkte schützen: 'oembed_response_data' Filter nutzen",
        "XML-RPC deaktivieren falls nicht benötigt",
        "Sitemap nur für Suchmaschinen, nicht für User-Enumeration",
    );

    if (@found_users > 0) {
        unshift @recs, "🔴 HANDLUNGSBEDARF: User Enumeration ist möglich!";
    }

    return @recs;  # ← Array zurückgeben, nicht Reference
}

sub print_recommendations {
    print_section("EMPFEHLUNGEN");

    my @recs = get_recommendations_array();  # ← Array, nicht Reference

    foreach my $rec (@recs) {
        print "$rec\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
WORDPRESS USER ENUMERATION TESTER v1.0
================================================================================

BESCHREIBUNG:
  Testet verschiedene Methoden, um WordPress-Benutzernamen auszulesen:
  • Author Archive (?author=N)
  • REST API (/wp-json/wp/v2/users)
  • Login-Fehlermeldungen
  • RSS-Feeds
  • Kommentare
  • Sitemaps
  • oEmbed-Endpunkte
  • Timing-Analyse (mit Wordlist)

VERWENDUNG:
  $0 --url <wordpress-url> [Optionen]

ERFORDERLICH:
  --url URL        WordPress-URL (z.B. https://example.com)

OPTIONEN:
  --max-users N    Maximale Anzahl zu findender User (Default: 20)
  --start-id N     Start-Author-ID (Default: 1)
  --end-id N       End-Author-ID (Default: 20)

  --wordlist DATEI Datei mit Benutzernamen für Timing-Analyse
  --threshold F    Schwellwert für Timing-Analyse (Default: 0.5 = 50%)

  --check-all      Alle Methoden testen (auch langsame)
  --timeout N      Timeout in Sekunden (Default: 10)
  --delay N        Pause zwischen Requests (Default: 0.5)

  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe
  --output DATEI   Ergebnisse als JSON speichern
  --user-agent UA  Eigenen User-Agent verwenden

  --cookie COOKIE  Session-Cookie
  --auth USER      Basic Auth Benutzername
  --auth-pass PASS Basic Auth Passwort

  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Einfacher Test
  $0 --url https://example.com

  # Mit Wordlist für Timing-Analyse
  $0 --url https://example.com --wordlist usernames.txt --threshold 0.3

  # Ausführlicher Test aller Methoden
  $0 --url https://example.com --check-all --verbose --start-id 1 --end-id 50

  # Mit JSON-Output
  $0 --url https://example.com --output users.json --verbose

HINWEISE:
  • Nur auf eigenen oder autorisierten Systemen testen!
  • User Enumeration ist oft der erste Schritt für Brute-Force
  • Viele WordPress-Seiten sind standardmäßig anfällig
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
WORDPRESS USER ENUMERATION TESTER v1.0
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

__END__
