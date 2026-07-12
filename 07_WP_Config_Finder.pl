#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent;
use Time::HiRes qw(time);
use Getopt::Long;
use Term::ANSIColor qw(:constants);
use JSON::PP;
use URI::Escape;
use File::Basename;

# ======================================================================
# WORDPRESS CONFIG LEAK TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Sucht nach exponierten WordPress-Konfigurationsdateien
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet auf:
#   • wp-config.php Backups (.bak, .old, .backup, ~)
#   • Editor-Temp-Dateien (.swp, .swo, .tmp)
#   • Debug-Logs (/wp-content/debug.log)
#   • Directory Indexing (/wp-content/uploads/)
#   • .htaccess / .git / .svn Dateien
#   • PHP-Fehlerlogs
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
    user_agent      => 'Mozilla/5.0 (WordPress Config Leak Tester)',
    delay           => 0.2,
    follow_redirects => 1,
    cookie          => '',
    auth_user       => '',
    auth_pass       => '',
    deep_scan       => 0,
    check_all       => 0,
    output_format   => 'text',
    max_files       => 100,
);

# ======================================================================
# LEECKDATEIEN - Wichtige Dateien und Pfade
# ======================================================================
my @config_files = (
    # wp-config.php Varianten
    'wp-config.php',
    'wp-config.php.bak',
    'wp-config.php.old',
    'wp-config.php.backup',
    'wp-config.php~',
    'wp-config.php.swp',
    'wp-config.php.swo',
    'wp-config.php.tmp',
    'wp-config.php.save',
    'wp-config.php.orig',
    'wp-config.php.original',
    'wp-config.php.copy',
    'wp-config.php.txt',
    'wp-config.php.html',
    'wp-config.php.bkp',
    'wp-config.php.1',
    'wp-config.php.old1',
    'wp-config.php.back',
    'wp-config.php_backup',
    'wp-config.php_old',
    'wp-config.php_bak',
    'backup-wp-config.php',
    'old-wp-config.php',
    'wp-config.inc',
    'config.php',
    'config.php.bak',
    'config.php.old',

    # Versteckte Versionen
    '.wp-config.php',
    '.wp-config.php.swp',
    '.wp-config.php.swo',
    '._wp-config.php',

    # Andere wichtige Configs
    '.htaccess',
    '.htaccess.bak',
    '.htaccess.old',
    '.htaccess~',
    '.htpasswd',
    '.user.ini',
    'php.ini',
    '.env',
    '.env.local',
    '.env.production',
    '.env.development',
    'environment.php',
    'config.php',
    'configuration.php',
    'settings.php',
    'database.php',
    'db.php',
    'db-config.php',
);

# ======================================================================
# LOG-DATEIEN
# ======================================================================
my @log_files = (
    # WordPress Logs
    'wp-content/debug.log',
    'wp-content/uploads/debug.log',
    'wp-content/debug.log.1',
    'wp-content/debug.log.gz',
    'wp-content/debug-log.txt',
    'wp-content/error.log',
    'wp-content/php-errors.log',

    # Allgemeine Logs
    'error_log',
    'error.log',
    'php_error.log',
    'php-errors.log',
    'debug.log',
    'logs/error.log',
    'logs/php-errors.log',
    'log.txt',
    'log.html',

    # Apache/Server Logs
    'access.log',
    'error.log',
    'logs/access.log',
    'logs/error.log',

    # Installations-Logs
    'install.log',
    'install.php',
    'setup.log',
    'upgrade.log',
);

# ======================================================================
# BACKUP-DATEIEN (allgemein)
# ======================================================================
my @backup_files = [
    # Komprimierte Backups
    'backup.zip',
    'backup.tar.gz',
    'backup.tar',
    'backup.sql',
    'backup.sql.gz',
    'dump.sql',
    'database.sql',
    'db_backup.sql',
    'wordpress_backup.zip',
    'wp_backup.zip',
    'site_backup.tar.gz',

    # Versionskontroll-Systeme
    '.git/config',
    '.git/index',
    '.git/HEAD',
    '.git/logs/HEAD',
    '.svn/entries',
    '.svn/wc.db',
    '.svn/format',
    '.bzr/README',
    '.hg/hgrc',

    # Composer/NPM
    'composer.json',
    'composer.lock',
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'bower.json',

    # READMEs mit Infos
    'readme.html',
    'readme.txt',
    'README.md',
    'license.txt',
    'changelog.txt',
];

# ======================================================================
# DIRECTORY INDEXING - Anfällige Verzeichnisse
# ======================================================================
my @index_dirs = [
    'wp-content/uploads/',
    'wp-content/uploads/2023/',
    'wp-content/uploads/2024/',
    'wp-content/uploads/2025/',
    'wp-content/uploads/2026/',
    'wp-content/backup/',
    'wp-content/backups/',
    'wp-content/cache/',
    'wp-content/upgrade/',
    'wp-content/updraft/',
    'wp-content/ai1wm-backups/',
    'wp-content/w3tc/',
    'wp-content/wflogs/',
    'wp-content/debug/',
    'wp-content/logs/',
    'wp-admin/backup/',
    'wp-includes/backup/',
    'backup/',
    'backups/',
    'db_backup/',
    'mysql_backup/',
    'old/',
    'temp/',
    'tmp/',
    'logs/',
    'log/',
];

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
    'deep-scan'       => \$config{deep_scan},
    'check-all'       => \$config{check_all},
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
my %found_leaks = ();
my @leaks = ();
my $total_requests = 0;

show_banner();
print_info("Ziel: $config{target_url}");
print_info("Timeout: $config{timeout} Sekunden");
print_info("Deep-Scan: " . ($config{deep_scan} ? "JA" : "NEIN"));

# User-Agent erstellen
my $ua = create_user_agent();

# ======================================================================
# 1. WORDPRESS BASIS-CHECK
# ======================================================================
print_section("WORDPRESS BASIS-CHECK");

my $wp_info = check_wordpress_basics($ua);
if (!$wp_info->{is_wordpress}) {
    print_warning("Kein WordPress erkannt - trotzdem nach Configs suchen?");
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
    if ($wp_info->{version}) {
        print_info("WordPress Version: $wp_info->{version}");
    }
    if ($wp_info->{theme}) {
        print_info("Aktives Theme: $wp_info->{theme}");
    }
}

# ======================================================================
# 2. WP-CONFIG DATEIEN SUCHEN
# ======================================================================
print_section("WP-CONFIG DATEIEN");

scan_config_files($ua);

# ======================================================================
# 3. LOG-DATEIEN SUCHEN
# ======================================================================
print_section("LOG-DATEIEN");

scan_log_files($ua);

# ======================================================================
# 4. BACKUP-DATEIEN SUCHEN
# ======================================================================
print_section("BACKUP-DATEIEN");

scan_backup_files($ua);

# ======================================================================
# 5. DIRECTORY INDEXING PRÜFEN
# ======================================================================
print_section("DIRECTORY INDEXING");

check_directory_indexing($ua);

# ======================================================================
# 6. VERSIONSKONTROLL-SYSTEME
# ======================================================================
print_section("VERSIONSKONTROLL-SYSTEME");

check_vcs_files($ua);

# ======================================================================
# 7. DEEP SCAN (OPTIONAL)
# ======================================================================
if ($config{deep_scan}) {
    print_section("DEEP SCAN");

    # Common backup locations
    deep_scan_backups($ua);

    # PHP info
    check_php_info($ua);
}

# ======================================================================
# 8. ERGEBNISSE ANZEIGEN
# ======================================================================
print_section("ERGEBNISSE");

show_results();

# ======================================================================
# 9. OUTPUT SPEICHERN
# ======================================================================
if ($config{output_json}) {
    save_output();
}

# ======================================================================
# 10. EMPFEHLUNGEN
# ======================================================================
print_recommendations();

# ======================================================================
# ABSCHLUSS
# ======================================================================
my $total_time = time() - $start_time;
print_info(sprintf("Gesamtzeit: %.2f Sekunden", $total_time));
print_info("Gefundene Leaks: " . scalar(@leaks));
print_info("Requests gesendet: $total_requests");

exit(scalar(@leaks) > 0 ? 1 : 0);

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
        max_size => 1024 * 1024 * 10,
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
    $ua->default_header('Accept-Language' => 'de,en-US;q=0.7,en;q=0.3');
    $ua->default_header('Connection' => 'keep-alive');

    return $ua;
}

sub check_wordpress_basics {
    my ($ua) = @_;
    my $info = { is_wordpress => 0 };

    my $resp = $ua->get($config{target_url});
    return $info unless $resp->is_success;

    my $content = $resp->content;

    # WordPress Indikatoren
    my @indicators = ('wp-content', 'wp-includes', 'wp-json', 'xmlrpc.php', 'WordPress');
    foreach my $ind (@indicators) {
        if ($content =~ /$ind/i) {
            $info->{is_wordpress} = 1;
            last;
        }
    }

    # WordPress Version
    if ($content =~ /<meta name="generator" content="WordPress ([0-9.]+)"/i) {
        $info->{version} = $1;
    }

    # Theme
    if ($content =~ /wp-content\/themes\/([^\/"]+)/) {
        $info->{theme} = $1;
    }

    return $info;
}

sub scan_config_files {
    my ($ua) = @_;
    my $found = 0;
    my $count = 0;

    foreach my $file (@config_files) {
        $count++;
        last if $count > $config{max_files} && !$config{deep_scan};

        my $url = "$config{target_url}/$file";
        print "  Teste: $file...\r" if $config{verbose};

        $total_requests++;
        my $resp = $ua->get($url);

        if ($resp->is_success) {
            my $size = length($resp->content);
            my $type = $resp->header('Content-Type') || 'unknown';

            # Prüfen ob es wirklich eine Config-Datei ist
            my $is_config = 0;
            my $content = $resp->content;

            if ($file =~ /wp-config\.php/i && $content =~ /define.*DB_|database|mysql|password|secret/i) {
                $is_config = 1;
            }
            elsif ($file =~ /\.(bak|old|backup|~|swp|swo)$/i && $content =~ /<?php|define|DB_/i) {
                $is_config = 1;
            }
            elsif ($file eq '.htaccess' && $content =~ /RewriteEngine|AuthType|Require/i) {
                $is_config = 1;
            }
            elsif ($file eq '.env' && $content =~ /APP_|DB_|PASSWORD|SECRET/i) {
                $is_config = 1;
            }
            else {
                $is_config = 1 if $size > 100;  # Verdächtig groß
            }

            if ($is_config) {
                $found++;
                my $leak = {
                    type => 'config',
                    file => $file,
                    url => $url,
                    size => $size,
                    content_type => $type,
                    status => $resp->code,
                    preview => substr($content, 0, 200),
                };
                push @leaks, $leak;
                $found_leaks{$file} = $leak;

                my $color = $file =~ /wp-config/i ? $RED : $YELLOW;
                print_color("$color  → GEFUNDEN: $file ($size bytes)$RESET");

                # Bei wp-config.php ersten Inhalt zeigen
                if ($file =~ /wp-config\.php/i && $config{verbose}) {
                    my @lines = split /\n/, $content;
                    foreach my $line (@lines) {
                        if ($line =~ /define.*DB_|password|secret|key/i) {
                            $line =~ s/(password|secret|key)=[^'\s]*/$1=***HIDDEN***/i;
                            print "      $line\n";
                        }
                    }
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Config-Dateien: $found gefunden");
}

sub scan_log_files {
    my ($ua) = @_;
    my $found = 0;

    foreach my $file (@log_files) {
        my $url = "$config{target_url}/$file";
        print "  Teste: $file...\r" if $config{verbose};

        $total_requests++;
        my $resp = $ua->get($url);

        if ($resp->is_success) {
            my $size = length($resp->content);
            my $content = $resp->content;

            # Logs erkennen
            my $is_log = 0;
            if ($content =~ /error|warning|notice|fatal|php|mysql|database|stack trace/i) {
                $is_log = 1;
            }
            elsif ($size > 1000 && $content =~ /[0-9]{4}-[0-9]{2}-[0-9]{2}/) {
                $is_log = 1;  # Datumsformat
            }

            if ($is_log) {
                $found++;
                my $leak = {
                    type => 'log',
                    file => $file,
                    url => $url,
                    size => $size,
                    status => $resp->code,
                    preview => substr($content, 0, 500),
                };
                push @leaks, $leak;
                $found_leaks{$file} = $leak;

                print_color("$YELLOW  → LOG GEFUNDEN: $file ($size bytes)$RESET");

                if ($config{verbose}) {
                    my @lines = split /\n/, $content;
                    my $count = 0;
                    foreach my $line (@lines) {
                        last if $count++ > 5;
                        next if $line =~ /^\s*$/;
                        $line =~ s/\s+$//;
                        print "      $line\n";
                    }
                    print "      ...\n" if @lines > 5;
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Log-Dateien: $found gefunden");
}

sub scan_backup_files {
    my ($ua) = @_;
    my $found = 0;

    foreach my $file (@backup_files) {
        my $url = "$config{target_url}/$file";
        print "  Teste: $file...\r" if $config{verbose};

        $total_requests++;
        my $resp = $ua->get($url);

        if ($resp->is_success) {
            my $size = length($resp->content);
            $found++;

            my $leak = {
                type => 'backup',
                file => $file,
                url => $url,
                size => $size,
                status => $resp->code,
            };
            push @leaks, $leak;
            $found_leaks{$file} = $leak;

            my $color = $file =~ /\.(sql|gz|zip)$/ ? $RED : $YELLOW;
            print_color("$color  → BACKUP GEFUNDEN: $file ($size bytes)$RESET");
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Backup-Dateien: $found gefunden");
}

sub check_directory_indexing {
    my ($ua) = @_;
    my $found = 0;

    foreach my $dir (@index_dirs) {
        my $url = "$config{target_url}/$dir";
        print "  Teste: $dir...\r" if $config{verbose};

        $total_requests++;
        my $resp = $ua->get($url);

        # Directory Indexing erkennen
        if ($resp->is_success) {
            my $content = $resp->content;

            # Typische Directory-Listing Indikatoren
            if ($content =~ /<title>Index of|Parent Directory|<a href="[^"]+\/">/i) {
                $found++;

                my $leak = {
                    type => 'directory_index',
                    directory => $dir,
                    url => $url,
                    status => $resp->code,
                    preview => substr($content, 0, 500),
                };
                push @leaks, $leak;
                $found_leaks{$dir} = $leak;

                print_color("$RED  → DIRECTORY INDEXING: $dir$RESET");

                if ($config{verbose}) {
                    # Zeige erste paar Dateien
                    my @files = ($content =~ /<a href="([^"]+\/)">[^<]+<\/a>/gi);
                    my $count = 0;
                    foreach my $f (@files) {
                        last if $count++ > 10;
                        print "      - $f\n";
                    }
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Directory Indexing: $found gefunden");
}

sub check_vcs_files {
    my ($ua) = @_;
    my $found = 0;

    my @vcs_files = (
        '.git/config',
        '.git/HEAD',
        '.git/index',
        '.git/logs/HEAD',
        '.svn/entries',
        '.svn/wc.db',
        '.svn/format',
        '.hg/hgrc',
        '.hg/requires',
        '.bzr/README',
    );

    foreach my $file (@vcs_files) {
        my $url = "$config{target_url}/$file";
        print "  Teste: $file...\r" if $config{verbose};

        $total_requests++;
        my $resp = $ua->get($url);

        if ($resp->is_success) {
            $found++;
            my $leak = {
                type => 'vcs',
                file => $file,
                url => $url,
                status => $resp->code,
                size => length($resp->content),
            };
            push @leaks, $leak;
            $found_leaks{$file} = $leak;

            print_color("$RED  → VCS GEFUNDEN: $file$RESET");
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("VCS-Dateien: $found gefunden");
}

sub deep_scan_backups {
    my ($ua) = @_;
    my $found = 0;

    # Häufige Backup-Verzeichnisse
    my @backup_dirs = (
        'backup/', 'backups/', 'old/', 'old_site/',
        'wp-content/backup/', 'wp-content/backups/',
        'wp-admin/backup/', 'wp-includes/backup/',
        'temp/', 'tmp/', 'temp_backup/',
    );

    foreach my $dir (@backup_dirs) {
        my $url = "$config{target_url}/$dir";
        print "  Durchsuche: $dir...\r" if $config{verbose};

        $total_requests++;
        my $resp = $ua->get($url);

        if ($resp->is_success && $resp->content =~ /<title>Index of/i) {
            my $content = $resp->content;
            my @files = ($content =~ /<a href="([^"]+\.(?:zip|tar|gz|sql|bak))"/gi);

            foreach my $file (@files) {
                my $file_url = "$url$file";
                print "    → Backupdatei: $file\n" if $config{verbose};

                $found_leaks{"$dir$file"} = {
                    type => 'backup_file',
                    file => "$dir$file",
                    url => $file_url,
                };
                $found++;
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("Deep-Scan Backups: $found gefunden");
}

sub check_php_info {
    my ($ua) = @_;

    my @php_info_paths = (
        'phpinfo.php',
        'info.php',
        'php-info.php',
        'test.php',
        'i.php',
        'info/phpinfo.php',
        'wp-admin/phpinfo.php',
    );

    foreach my $path (@php_info_paths) {
        my $url = "$config{target_url}/$path";
        $total_requests++;
        my $resp = $ua->get($url);

        if ($resp->is_success && $resp->content =~ /phpinfo|PHP Version|PHP License/i) {
            my $leak = {
                type => 'phpinfo',
                file => $path,
                url => $url,
                status => $resp->code,
            };
            push @leaks, $leak;
            $found_leaks{$path} = $leak;

            print_color("$RED  → PHPINFO GEFUNDEN: $path$RESET");
        }

        sleep($config{delay}) if $config{delay} > 0;
    }
}

sub show_results {
    print "\n" . "=" x 60 . "\n";
    print "GEFUNDENE LEAKS (" . scalar(@leaks) . "):\n";
    print "=" x 60 . "\n";

    if (@leaks == 0) {
        print "✅ Keine Konfigurations-Leaks gefunden.\n";
        print "Die Seite scheint gut konfiguriert zu sein.\n";
    } else {
        # Nach Schweregrad sortieren
        my @critical = grep { $_->{type} eq 'config' && $_->{file} =~ /wp-config/i } @leaks;
        my @high = grep { $_->{type} eq 'config' || $_->{type} eq 'backup' } @leaks;
        my @medium = grep { $_->{type} eq 'log' || $_->{type} eq 'directory_index' } @leaks;
        my @low = grep { $_->{type} eq 'vcs' } @leaks;

        if (@critical) {
            print "$RED🔴 KRITISCHE LEAKS (" . scalar(@critical) . "):$RESET\n";
            foreach my $leak (@critical) {
                print "  • $leak->{file} - $leak->{url}\n";
            }
        }

        if (@high) {
            print "$YELLOW🟡 HOHE RISIKEN (" . scalar(@high) . "):$RESET\n";
            foreach my $leak (@high) {
                print "  • $leak->{file} - $leak->{url}\n";
            }
        }

        if (@medium) {
            print "$CYAN🔵 MITTLERE RISIKEN (" . scalar(@medium) . "):$RESET\n";
            foreach my $leak (@medium) {
                print "  • $leak->{file} - $leak->{url}\n";
            }
        }

        if (@low) {
            print "🟢 GERINGE RISIKEN (" . scalar(@low) . "):\n";
            foreach my $leak (@low) {
                print "  • $leak->{file} - $leak->{url}\n";
            }
        }
    }
}

sub save_output {
    my $output = {
        tool => "WordPress Config Leak Tester",
        version => "1.0",
        timestamp => scalar(localtime()),
        target => $config{target_url},
        config => \%config,
        statistics => {
            total_leaks => scalar(@leaks),
            critical => scalar(grep { $_->{type} eq 'config' && $_->{file} =~ /wp-config/i } @leaks),
            high => scalar(grep { $_->{type} eq 'config' || $_->{type} eq 'backup' } @leaks),
            medium => scalar(grep { $_->{type} eq 'log' || $_->{type} eq 'directory_index' } @leaks),
            low => scalar(grep { $_->{type} eq 'vcs' } @leaks),
            total_requests => $total_requests,
            scan_time => time() - $start_time,
        },
        leaks => \@leaks,
    };

    if ($config{output_format} eq 'json' || $config{output_json} =~ /\.json$/) {
        my $json = JSON::PP->new->pretty->encode($output);
        open(my $fh, '>', $config{output_json}) or die "Kann Datei nicht öffnen: $!";
        print $fh $json;
        close($fh);
        print_success("JSON gespeichert: $config{output_json}");
    }
    elsif ($config{output_format} eq 'csv' || $config{output_json} =~ /\.csv$/) {
        open(my $fh, '>', $config{output_json}) or die "Kann Datei nicht öffnen: $!";
        print $fh "Typ,Datei/Pfad,URL,Status\n";
        foreach my $leak (@leaks) {
            my $path = $leak->{file} || $leak->{directory} || '';
            print $fh "$leak->{type},$path,$leak->{url},$leak->{status}\n";
        }
        close($fh);
        print_success("CSV gespeichert: $config{output_json}");
    }
}

sub print_recommendations {
    print_section("EMPFEHLUNGEN");

    my @recs = (
        "• wp-config.php Zugriff schützen (Dateirechte 600/640)",
        "• Backup-Dateien vom Server entfernen",
        "• Debug-Logging deaktivieren: WP_DEBUG auf false",
        "• Directory Indexing in .htaccess deaktivieren: Options -Indexes",
        "• .git und .svn Verzeichnisse vom Server entfernen",
        "• phpinfo() Dateien löschen",
        "• Regelmäßige Sicherheits-Scans durchführen",
    );

    if (grep { $_->{type} eq 'config' && $_->{file} =~ /wp-config/i } @leaks) {
        unshift @recs, "🔴 SOFORT HANDELN! wp-config.php ist öffentlich lesbar!";
    }

    if (grep { $_->{type} eq 'log' } @leaks) {
        unshift @recs, "🟡 Log-Dateien enthalten oft sensible Daten - sofort löschen!";
    }

    if (grep { $_->{type} eq 'directory_index' } @leaks) {
        unshift @recs, "🟡 Directory Indexing deaktivieren (Options -Indexes)";
    }

    foreach (@recs) {
        print "$_\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
WORDPRESS CONFIG LEAK TESTER v1.0
================================================================================

BESCHREIBUNG:
  Sucht nach exponierten Konfigurationsdateien, Backups, Logs und
  Directory Indexing in WordPress-Installationen.

GETESTETE SCHWACHSTELLEN:
  • wp-config.php Backups (.bak, .old, ~, .swp)
  • Log-Dateien (debug.log, error_log)
  • Backup-Archive (.zip, .tar.gz, .sql)
  • Directory Indexing (/wp-content/uploads/)
  • Versionskontroll-Systeme (.git, .svn)
  • phpinfo() Ausgaben

VERWENDUNG:
  $0 --url <wordpress-url> [Optionen]

OPTIONEN:
  --url URL        WordPress-URL (z.B. https://example.com)

  --deep-scan      Intensivere Suche (Backup-Verzeichnisse durchsuchen)
  --timeout N      Timeout in Sekunden (Default: 10)
  --delay N        Pause zwischen Requests (Default: 0.2)

  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe
  --output DATEI   Ergebnisse speichern
  --format FORMAT  text, json, csv (Default: text)
  --user-agent UA  Eigenen User-Agent verwenden

  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Standard-Scan
  $0 --url https://example.com

  # Deep-Scan mit JSON-Output
  $0 --url https://example.com --deep-scan --output leaks.json

  # Ausführlicher Scan
  $0 --url https://example.com --verbose --delay 0

HINWEISE:
  • Nur auf eigenen oder autorisierten Systemen testen!
  • Config-Leaks können zu vollständiger Kompromittierung führen
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
WORDPRESS CONFIG LEAK TESTER v1.0
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
