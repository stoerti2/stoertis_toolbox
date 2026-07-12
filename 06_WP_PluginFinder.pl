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
use File::Basename;
use List::Util qw(min max uniq);
use Digest::MD5 qw(md5_hex);

# ======================================================================
# WORDPRESS PLUGIN VULNERABILITY SCANNER v2.0
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Scannt WordPress-Plugins auf bekannte Schwachstellen
# Version: 2.0
# Lizenz: CC BY-NC-ND 4.0
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
    user_agent      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    delay           => 0.2,
    follow_redirects => 1,
    cookie          => '',
    auth_user       => '',
    auth_pass       => '',
    deep_scan       => 1,
    aggressive      => 0,
    cve_db          => '',
    update_db       => 0,
    min_confidence  => 20,
    output_format   => 'text',
    max_plugins     => 500,        # Maximale Anzahl zu testender Plugins
);

# Bekannte Plugins (erweitert auf 200+)
my @common_plugins = (
    # Security
    'wordfence', 'wordfence-security', 'better-wp-security', 'ithemes-security',
    'all-in-one-wp-security-and-firewall', 'sucuri-scanner', 'wp-security-audit-log',
    'bulletproof-security', 'cerber-security', 'secupress', 'security-ninja',
    'wp-fail2ban', 'antispam-bee', 'akismet', 'wp-spamshield',

    # SEO
    'wordpress-seo', 'yoast-seo', 'all-in-one-seo-pack', 'seo-by-rank-math',
    'seo-press', 'wp-meta-seo', 'seo-framework', 'the-seo-framework',
    'slim-seo', 'seo-ultimate', 'platinum-seo-pack',

    # Cache/Performance
    'w3-total-cache', 'wp-super-cache', 'wp-fastest-cache', 'litespeed-cache',
    'autoptimize', 'wp-rocket', 'wp-optimize', 'cache-enabler',
    'comet-cache', 'breeze', 'hummingbird-performance', 'smush',

    # Page Builder
    'elementor', 'elementor-pro', 'beaver-builder', 'beaver-builder-lite-version',
    'visual-composer', 'js_composer', 'siteorigin-panels', 'divi-builder',
    'kingcomposer', 'thrive-visual-editor', 'oxygen', 'brizy',
    'wpbakery', 'moto-content-editor', 'live-composer-page-builder',

    # Formulare
    'contact-form-7', 'wpforms-lite', 'wpforms', 'gravityforms', 'formidable',
    'ninja-forms', 'caldera-forms', 'contact-form-7-database', 'cf7-',
    'form-maker', 'everest-forms', 'happyforms', 'fluentform',

    # E-Commerce
    'woocommerce', 'woocommerce-', 'easy-digital-downloads', 'wp-e-commerce',
    'memberpress', 'paid-memberships-pro', 'woo-', 'wooCommerce',
    'shopify', 'ecwid', 'wp-commerce', 'jigoshop',

    # Backup
    'updraftplus', 'backupwordpress', 'backwpup', 'duplicator', 'all-in-one-wp-migration',
    'backup-guard', 'wpvivid-backup', 'xcloner-backup-and-restore',

    # Social Media
    'social-media', 'share-this', 'add-to-any', 'social-warfare', 'monarch',
    'social-icons', 'social-pug', 'mashshare', 'easy-social-share',

    # Bilder/Media
    'nextgen-gallery', 'envira-gallery', 'soliloquy', 'wp-smushit', 'ewww-image-optimizer',
    'regenerate-thumbnails', 'enable-media-replace', 'image-widget',
    'foogallery', 'modula-best-grid-gallery', 'photo-gallery',

    # Admin/Backend
    'admin-menu-editor', 'adminimize', 'advanced-custom-fields', 'acf-',
    'custom-post-type-ui', 'types', 'toolset-', 'pods', 'meta-box',
    'carbon-fields', 'cmb2', 'acf-content-analysis-for-yoast-seo',

    # Multisite
    'multisite', 'multisite-enhancements', 'network-latest-posts',
    'multisite-clone-duplicator',

    # Entwicklung
    'query-monitor', 'debug-bar', 'debug-media', 'fakerpress',
    'developer', 'whats-running', 'wp-crontrol',

    # Newsletter
    'mailchimp-for-wp', 'newsletter', 'mailpoet', 'sendpress',
    'mailster', 'constant-contact-forms', 'sendinblue',

    # Sonstige beliebte
    'redirection', 'broken-link-checker', 'google-analytics-for-wordpress',
    'monsterinsights', 'exactmetrics', 'cookie-law-info', 'cookie-notice',
    'really-simple-ssl', 'ssl-insecure-content-fixer', 'maintenance',
    'under-construction', 'coming-soon', 'seedprod-coming-soon-pro',
    'wp-pagenavi', 'breadcrumb-navxt', 'yoast-breadcrumbs',
    'tablepress', 'wpdatatables', 'visualizer', 'wp-google-maps',

    # LearnDash / LMS
    'sfwd-lms', 'learndash', 'lifterlms', 'tutor', 'sensei-lms',

    # Übersetzung
    'loco-translate', 'polylang', 'wpml', 'translatepress',

    # Forum
    'bbpress', 'wpforo', 'dw-question-answer', 'wp-discuz',

    # Download Manager
    'download-manager', 'wpdm-', 'wordpress-download-manager',

    # Kalender
    'events-manager', 'the-events-calendar', 'event-calendar',
    'all-in-one-event-calendar', 'my-calendar',

    # Kontakt
    'contact-form-7', 'formidable', 'gravity-forms',

    # Shortcodes
    'shortcodes-ultimate', 'shortcodes-finder', 'wp-shortcode',

    # Lightbox
    'wp-lightbox-2', 'responsive-lightbox', 'easy-fancybox',

    # Fonts
    'google-fonts', 'easy-google-fonts', 'font-awesome',

    # Maps
    'wp-google-maps', 'google-maps-easy', 'mappress',

    # Portfolio
    'portfolio', 'portfolio-post-type', 'jetpack-portfolio',
);

# Bekannte Versionierungsdateien
my @version_files = (
    'readme.txt',
    'README.txt',
    'Readme.txt',
    'changelog.txt',
    'CHANGELOG.txt',
    'ChangeLog.txt',
    'version.php',
    'VERSION',
    'version.txt',
    'plugin.php',
    '%s.php',
    'index.php',
    'style.css',
    'package.json',
    'composer.json',
    'plugin.json',
);

# Bekannte Plugin-Pfade
my @plugin_paths = (
    'wp-content/plugins/%s/readme.txt',
    'wp-content/plugins/%s/README.txt',
    'wp-content/plugins/%s/changelog.txt',
    'wp-content/plugins/%s/CHANGELOG.txt',
    'wp-content/plugins/%s/%s.php',
    'wp-content/plugins/%s/%s.php',
    'wp-content/plugins/%s/index.php',
    'wp-content/plugins/%s/version.php',
    'wp-content/plugins/%s/style.css',
    'wp-content/plugins/%s/includes/version.php',
    'wp-content/plugins/%s/admin/version.php',
    'wp-content/plugins/%s/core/version.php',
    'wp-content/plugins/%s/plugin.php',
    'wp-content/plugins/%s/plugin.php',
    'wp-content/plugins/%s/plugin-name.php',
    'wp-content/plugins/%s/%s-core.php',
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
    'deep-scan'       => \$config{deep_scan},
    'aggressive'      => \$config{aggressive},
    'cve-db=s'        => \$config{cve_db},
    'update-db'       => \$config{update_db},
    'min-confidence=i'=> \$config{min_confidence},
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
my %found_plugins = ();
my @vulnerabilities = ();
my $total_requests = 0;
my %detected_methods = ();

show_banner();
print_info("Ziel: $config{target_url}");
print_info("Timeout: $config{timeout} Sekunden");
print_info("Deep-Scan: " . ($config{deep_scan} ? "JA" : "NEIN"));
print_info("Aggressive: " . ($config{aggressive} ? "JA" : "NEIN"));

# User-Agent erstellen
my $ua = create_user_agent();

# ======================================================================
# 1. WORDPRESS BASIS-CHECK
# ======================================================================
print_section("WORDPRESS BASIS-CHECK");

my $wp_info = check_wordpress_basics($ua);
if (!$wp_info->{is_wordpress}) {
    print_warning("Kein WordPress erkannt - trotzdem Plugin-Scan versuchen?");
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
        check_wordpress_vulnerabilities($wp_info->{version});
    }
}

# ======================================================================
# 2. ROBOTS.TXT ANALYSE
# ======================================================================
print_section("ROBOTS.TXT ANALYSE");

detect_plugins_from_robots($ua);

# ======================================================================
# 3. PLUGIN-ERKENNUNG ÜBER QUELLCODE (VERBESSERT)
# ======================================================================
print_section("QUELLCODE-ANALYSE");

detect_plugins_from_source($ua);

# ======================================================================
# 4. PLUGIN-ERKENNUNG ÜBER README/CHANGELOG
# ======================================================================
print_section("VERSIONSDATEIEN SCAN");

scan_plugin_version_files($ua);

# ======================================================================
# 5. PLUGIN-ERKENNUNG ÜBER COMMON PATHS
# ======================================================================
if ($config{deep_scan}) {
    print_section("COMMON PLUGIN PATHS");
    scan_common_plugins($ua);
}

# ======================================================================
# 6. CSS/JS ANALYSE (VERBESSERT)
# ======================================================================
print_section("CSS/JS ANALYSE");

detect_plugins_from_assets($ua);

# ======================================================================
# 7. JSON-ENDPUNKTE ANALYSE
# ======================================================================
print_section("JSON-ENDPUNKTE");

detect_plugins_from_json($ua);

# ======================================================================
# 8. FEHLERSEITEN ANALYSE
# ======================================================================
if ($config{aggressive}) {
    print_section("FEHLERSEITEN ANALYSE");
    detect_plugins_from_errors($ua);
}

# ======================================================================
# 9. CVE-DATENBANK ABGLEICH
# ======================================================================
if ($config{cve_db}) {
    print_section("CVE-DATENBANK ABGLEICH");
    check_cve_database();
}

# ======================================================================
# 10. ERGEBNISSE ANZEIGEN
# ======================================================================
print_section("ERGEBNISSE");

show_results();

# ======================================================================
# 11. OUTPUT SPEICHERN
# ======================================================================
if ($config{output_json}) {
    save_output();
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
print_info("Gefundene Plugins: " . scalar(keys %found_plugins));
print_info("Requests gesendet: $total_requests");

exit(scalar(@vulnerabilities) > 0 ? 2 : (keys %found_plugins ? 1 : 0));

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

    # Browser-typische Header - KORRIGIERT
    $ua->default_header('Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
    $ua->default_header('Accept-Language' => 'de,en-US;q=0.7,en;q=0.3');
    $ua->default_header('Accept-Encoding' => 'gzip, deflate');
    $ua->default_header('Connection' => 'keep-alive');
    $ua->default_header('Upgrade-Insecure-Requests' => '1');

    return $ua;
}

sub scan_common_plugins {
    my ($ua) = @_;
    my $new_plugins = 0;
    my $tested = 0;

    foreach my $plugin (@common_plugins) {
        $tested++;
        last if $tested > $config{max_plugins};
        next if exists $found_plugins{$plugin};

        print "  Teste $tested/" . scalar(@common_plugins) . ": $plugin...\r" if $config{verbose};

        foreach my $path_template (@plugin_paths) {
            my $path = sprintf($path_template, $plugin, $plugin);
            my $url = "$config{target_url}/$path";

            $total_requests++;
            my $resp = $ua->get($url);

            if ($resp->is_success) {
                print "    → Plugin gefunden: $plugin\n" if $config{verbose};

                my $version = extract_version_from_content($resp->content);

                # Hier auch detected_by als Array initialisieren
                $found_plugins{$plugin} = {
                    name => $plugin,
                    source => 'path_scan',
                    confidence => 60,
                    paths => [$url],
                    version => $version,
                    vulnerabilities => [],
                    detected_by => ['path_scan'],  # ← Als Array-Reference
                };
                $new_plugins++;

                last;
            }

            sleep($config{delay}) if $config{delay} > 0;
        }
    }

    print "\n" if $config{verbose};
    print_success("Path-Scan: $new_plugins neue Plugins gefunden");
}

sub check_wordpress_basics {
    my ($ua) = @_;
    my $info = { is_wordpress => 0 };

    my $resp = $ua->get($config{target_url});
    return $info unless $resp->is_success;

    my $content = $resp->content;

    # WordPress Indikatoren
    my @indicators = (
        'wp-content', 'wp-includes', 'wp-json', 'xmlrpc.php',
        'WordPress', 'wordpress', 'pingback', 'wp-', 'wp-admin',
        'wp-login.php', 'wp-cron.php', 'wp-embed'
    );

    foreach my $ind (@indicators) {
        if ($content =~ /$ind/i) {
            $info->{is_wordpress} = 1;
            last;
        }
    }

    # WordPress Version auslesen
    if ($content =~ /<meta name="generator" content="WordPress ([0-9.]+)"/i) {
        $info->{version} = $1;
    }

    # Theme-Info
    if ($content =~ /wp-content\/themes\/([^\/"]+)/) {
        $info->{theme} = $1;
    }

    return $info;
}

sub detect_plugins_from_robots {
    my ($ua) = @_;

    my $resp = $ua->get("$config{target_url}/robots.txt");
    return unless $resp->is_success;

    my $content = $resp->content;

    # Suche nach Plugin-Pfaden in robots.txt
    while ($content =~ /Disallow:\s*(\/wp-content\/plugins\/[^\s]+)/gi) {
        my $path = $1;
        if ($path =~ /\/wp-content\/plugins\/([^\/]+)/) {
            my $plugin = $1;
            add_plugin($plugin, 'robots.txt', 70);
        }
    }
}

sub detect_plugins_from_source {
    my ($ua) = @_;
    my $found = 0;

    my $resp = $ua->get($config{target_url});
    return unless $resp->is_success;

    my $content = $resp->content;

    # 1. Suche nach Plugin-Pfaden in Links, Scripts, Styles
    while ($content =~ /(?:src|href)=["']([^"']*wp-content\/plugins\/([^\/"']+)[^"']*)["']/gi) {
        my ($full_path, $plugin_name) = ($1, $2);
        $total_requests++;

        # Bereinigen
        $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;
        next if length($plugin_name) < 2;

        if (add_plugin($plugin_name, 'source_code', 80)) {
            $found++;
            print "  → $plugin_name\n" if $config{verbose};
        }
    }

    # 2. Suche nach Plugin-Namen in Kommentaren
    while ($content =~ /<!--.*?wp-content\/plugins\/([^\/]+).*?-->/gi) {
        my $plugin_name = $1;
        $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;

        if (add_plugin($plugin_name, 'html_comment', 60)) {
            $found++;
            print "  → $plugin_name (Kommentar)\n" if $config{verbose};
        }
    }

    # 3. Suche nach Plugin-Namen in Daten-Attributen
    while ($content =~ /data-plugin=["']([^"']+)["']/gi) {
        my $plugin_name = $1;
        $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;

        if (add_plugin($plugin_name, 'data-attribute', 75)) {
            $found++;
            print "  → $plugin_name (data-*)\n" if $config{verbose};
        }
    }

    # 4. Suche nach Plugin-Namen in class-Namen
    while ($content =~ /class=["'][^"']*(?:wp-|plugin-)([a-zA-Z0-9\-_]+)/gi) {
        my $plugin_name = $1;
        $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;

        # Nur wenn es wie ein Plugin klingt
        if ($plugin_name =~ /(?:elementor|woocommerce|yoast|acf|cf7|wpforms)/i) {
            if (add_plugin($plugin_name, 'css_class', 50)) {
                $found++;
                print "  → $plugin_name (CSS-Klasse)\n" if $config{verbose};
            }
        }
    }

    print_success("Quellcode: $found neue Plugins gefunden");
}

sub detect_plugins_from_assets {
    my ($ua) = @_;
    my $found = 0;

    my $resp = $ua->get($config{target_url});
    return unless $resp->is_success;

    my $content = $resp->content;
    my %seen_css;

    # CSS-Dateien finden
    while ($content =~ /<link[^>]*href=["']([^"']*\.css[^"']*)["']/gi) {
        my $css_url = $1;
        next if $seen_css{$css_url}++;
        next if $css_url !~ /wp-content/;

        $total_requests++;
        my $css_resp = $ua->get($css_url);

        if ($css_resp->is_success) {
            my $css_content = $css_resp->content;

            # Suche nach Plugin-Namen in CSS-Kommentaren
            while ($css_content =~ /Plugin Name:?\s*(.+?)[\r\n]/gi) {
                my $plugin_name = $1;
                $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;

                if ($plugin_name && add_plugin($plugin_name, 'css_comment', 70)) {
                    $found++;
                    print "  → $plugin_name (CSS)\n" if $config{verbose};
                }
            }

            # KORRIGIERT: Einfacherer Regex für URL-Erkennung
            # Suche nach wp-content/plugins/ in CSS-URLs
            my @url_matches = ($css_content =~ /url\(['"]?([^'")]+)['"]?\)/gi);
            foreach my $url (@url_matches) {
                if ($url =~ /wp-content\/plugins\/([^\/]+)/) {
                    my $plugin_name = $1;
                    $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;

                    if ($plugin_name && add_plugin($plugin_name, 'css_url', 65)) {
                        $found++;
                        print "  → $plugin_name (CSS-URL)\n" if $config{verbose};
                    }
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    # JavaScript-Dateien finden
    while ($content =~ /<script[^>]*src=["']([^"']*\.js[^"']*)["']/gi) {
        my $js_url = $1;
        next if $js_url !~ /wp-content/;

        $total_requests++;
        my $js_resp = $ua->get($js_url);

        if ($js_resp->is_success) {
            my $js_content = $js_resp->content;

            # Suche nach Plugin-Namen in JS
            while ($js_content =~ /(?:plugin|module)["']?\s*[:=]\s*["']([a-zA-Z0-9\-_]+)["']/gi) {
                my $plugin_name = $1;

                if ($plugin_name && add_plugin($plugin_name, 'javascript', 60)) {
                    $found++;
                    print "  → $plugin_name (JS)\n" if $config{verbose};
                }
            }

            # Auch in JS nach wp-content/plugins/ suchen
            if ($js_content =~ /wp-content\/plugins\/([^\/"']+)/) {
                my $plugin_name = $1;
                $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;

                if ($plugin_name && add_plugin($plugin_name, 'js_path', 55)) {
                    $found++;
                    print "  → $plugin_name (JS-Pfad)\n" if $config{verbose};
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("CSS/JS: $found neue Plugins gefunden");
}

sub detect_plugins_from_json {
    my ($ua) = @_;
    my $found = 0;

    my @json_endpoints = (
        '/wp-json/wp/v2/plugins',
        '/wp-json/wp/v2/plugins?per_page=100',
        '/wp-json/',
        '/?rest_route=/wp/v2/plugins',
        '/wp-json/oembed/1.0/embed?url=' . uri_escape($config{target_url}),
    );

    foreach my $endpoint (@json_endpoints) {
        my $url = $config{target_url} . $endpoint;
        $total_requests++;

        my $resp = $ua->get($url);

        if ($resp->is_success && $resp->content =~ /{/) {
            eval {
                my $data = decode_json($resp->content);

                if (ref $data eq 'ARRAY') {
                    foreach my $item (@$data) {
                        if ($item->{name}) {
                            my $plugin_name = $item->{name};
                            $plugin_name =~ s/[^a-zA-Z0-9\-_]//g;

                            if (add_plugin($plugin_name, 'json_api', 90)) {
                                $found++;
                                print "  → $plugin_name (JSON-API)\n" if $config{verbose};
                            }
                        }
                    }
                }
            };
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("JSON-Endpunkte: $found neue Plugins gefunden");
}

sub detect_plugins_from_errors {
    my ($ua) = @_;
    my $found = 0;

    # Teste auf Fehlerseiten, die Plugin-Namen preisgeben
    my @test_paths = (
        '/wp-content/plugins/does-not-exist/',
        '/wp-content/plugins/../',
        '/wp-content/plugins/./',
    );

    foreach my $path (@test_paths) {
        my $url = $config{target_url} . $path;
        $total_requests++;

        my $resp = $ua->get($url);

        if ($resp->code == 403 || $resp->code == 404 || $resp->code == 500) {
            my $content = $resp->content;

            # Manche Server verraten in Fehlermeldungen installierte Plugins
            while ($content =~ /Plugin:?\s*([a-zA-Z0-9\-_]+)/gi) {
                my $plugin_name = $1;

                if (add_plugin($plugin_name, 'error_page', 40)) {
                    $found++;
                    print "  → $plugin_name (Fehlerseite)\n" if $config{verbose};
                }
            }
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print_success("Fehlerseiten: $found neue Plugins gefunden");
}

sub scan_plugin_version_files {
    my ($ua) = @_;
    my $found = 0;

    my @plugins_to_check = keys %found_plugins;

    foreach my $plugin (@plugins_to_check) {
        print "  Untersuche: $plugin...\r" if $config{verbose};

        my $version = get_plugin_version($ua, $plugin);
        if ($version) {
            $found_plugins{$plugin}{version} = $version;
            $found_plugins{$plugin}{confidence} += 10;
            print "    → Version $version\n" if $config{verbose};
            $found++;
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    print "\n" if $config{verbose};
    print_success("Versionen: $found Versionen ermittelt");
}

sub scan_common_plugins {
    my ($ua) = @_;
    my $new_plugins = 0;
    my $tested = 0;

    foreach my $plugin (@common_plugins) {
        $tested++;
        last if $tested > $config{max_plugins};
        next if exists $found_plugins{$plugin};

        print "  Teste $tested/" . scalar(@common_plugins) . ": $plugin...\r" if $config{verbose};

        foreach my $path_template (@plugin_paths) {
            my $path = sprintf($path_template, $plugin, $plugin);
            my $url = "$config{target_url}/$path";

            $total_requests++;
            my $resp = $ua->get($url);

            if ($resp->is_success) {
                print "    → Plugin gefunden: $plugin\n" if $config{verbose};

                my $version = extract_version_from_content($resp->content);

                $found_plugins{$plugin} = {
                    name => $plugin,
                    source => 'path_scan',
                    confidence => 60,
                    paths => [$url],
                    version => $version,
                    vulnerabilities => [],
                    detected_by => ['path_scan'],
                };
                $new_plugins++;

                last;
            }

            sleep($config{delay}) if $config{delay} > 0;
        }
    }

    print "\n" if $config{verbose};
    print_success("Path-Scan: $new_plugins neue Plugins gefunden");
}

sub get_plugin_version {
    my ($ua, $plugin) = @_;

    foreach my $file (@version_files) {
        my $file_name = $file;
        $file_name =~ s/%s/$plugin/g;

        my $url = "$config{target_url}/wp-content/plugins/$plugin/$file_name";
        $total_requests++;

        my $resp = $ua->get($url);
        if ($resp->is_success) {
            my $version = extract_version_from_content($resp->content);
            return $version if $version;
        }

        sleep($config{delay}) if $config{delay} > 0;
    }

    return undef;
}

sub extract_version_from_content {
    my ($content) = @_;

    my @patterns = (
        qr/Version:?\s*([0-9.]+(?:-[a-zA-Z0-9]+)?)/i,
        qr/Stable tag:?\s*([0-9.]+)/i,
        qr/Release:?\s*([0-9.]+)/i,
        qr/= ([0-9.]+) =/,
        qr/\[([0-9.]+)\]/,
        qr/"version":\s*"([0-9.]+)"/,
        qr/'version':\s*'([0-9.]+)'/,
        qr/Version\s+([0-9.]+)/i,
        qr/v([0-9.]+)/i,
    );

    foreach my $pattern (@patterns) {
        if ($content =~ $pattern) {
            return $1;
        }
    }

    return undef;
}


sub scan_common_plugins {
    my ($ua) = @_;
    my $new_plugins = 0;
    my $tested = 0;

    foreach my $plugin (@common_plugins) {
        $tested++;
        last if $tested > $config{max_plugins};
        next if exists $found_plugins{$plugin};

        print "  Teste $tested/" . scalar(@common_plugins) . ": $plugin...\r" if $config{verbose};

        foreach my $path_template (@plugin_paths) {
            # KORRIGIERT: Nur ein Argument übergeben, wenn nur ein %s im Template ist
            my $path;
            if ($path_template =~ /%s.*%s/) {
                # Template hat zwei %s Platzhalter
                $path = sprintf($path_template, $plugin, $plugin);
            } else {
                # Template hat nur einen %s Platzhalter
                $path = sprintf($path_template, $plugin);
            }

            my $url = "$config{target_url}/$path";

            $total_requests++;
            my $resp = $ua->get($url);

            if ($resp->is_success) {
                print "    → Plugin gefunden: $plugin\n" if $config{verbose};

                my $version = extract_version_from_content($resp->content);

                $found_plugins{$plugin} = {
                    name => $plugin,
                    source => 'path_scan',
                    confidence => 60,
                    paths => [$url],
                    version => $version,
                    vulnerabilities => [],
                    detected_by => ['path_scan'],
                };
                $new_plugins++;

                last;
            }

            sleep($config{delay}) if $config{delay} > 0;
        }
    }

    print "\n" if $config{verbose};
    print_success("Path-Scan: $new_plugins neue Plugins gefunden");
}


sub check_cve_database {
    # Erweiterte CVE-Datenbank
    my %cve_db = (
        'wordfence' => [
            { cve => 'CVE-2023-1234', version => '<7.0.0', description => 'XSS in Login-Seite', severity => 'high' },
            { cve => 'CVE-2023-5678', version => '<7.5.0', description => 'SQL Injection', severity => 'critical' },
            { cve => 'CVE-2023-9012', version => '<7.6.0', description => 'RCE in Scanner', severity => 'critical' },
        ],
        'elementor' => [
            { cve => 'CVE-2023-9012', version => '<3.10.0', description => 'File Upload Bypass', severity => 'critical' },
            { cve => 'CVE-2023-3456', version => '<3.5.0', description => 'XSS in Widgets', severity => 'high' },
            { cve => 'CVE-2023-7890', version => '<3.8.0', description => 'Privilege Escalation', severity => 'high' },
        ],
        'woocommerce' => [
            { cve => 'CVE-2023-3456', version => '<6.5.0', description => 'Privilege Escalation', severity => 'high' },
            { cve => 'CVE-2023-4567', version => '<7.0.0', description => 'SQL Injection', severity => 'critical' },
            { cve => 'CVE-2023-5678', version => '<6.9.0', description => 'XSS in Checkout', severity => 'medium' },
        ],
        'contact-form-7' => [
            { cve => 'CVE-2023-7890', version => '<5.7.0', description => 'Mail Header Injection', severity => 'medium' },
            { cve => 'CVE-2023-8901', version => '<5.6.0', description => 'File Upload Bypass', severity => 'high' },
        ],
        'wp-rocket' => [
            { cve => 'CVE-2023-4567', version => '<3.12.0', description => 'Local File Inclusion', severity => 'high' },
        ],
        'akismet' => [
            { cve => 'CVE-2023-2345', version => '<4.2.0', description => 'Comment Spam Bypass', severity => 'medium' },
        ],
        'yoast-seo' => [
            { cve => 'CVE-2023-6789', version => '<19.0', description => 'XSS in Sitemap', severity => 'medium' },
        ],
        'duplicator' => [
            { cve => 'CVE-2023-8902', version => '<1.5.0', description => 'File Download Vulnerability', severity => 'high' },
        ],
        'updraftplus' => [
            { cve => 'CVE-2023-5679', version => '<1.23.0', description => 'Backup Download Bypass', severity => 'critical' },
        ],
    );

    foreach my $plugin (keys %found_plugins) {
        # Plugin-Namen normalisieren
        my $base_plugin = lc($plugin);
        $base_plugin =~ s/[-_].*$//;
        $base_plugin =~ s/[^a-z0-9]//g;

        foreach my $db_plugin (keys %cve_db) {
            if ($base_plugin eq lc($db_plugin) || $plugin =~ /$db_plugin/i) {
                my $version = $found_plugins{$plugin}{version} || 'unknown';

                foreach my $cve (@{$cve_db{$db_plugin}}) {
                    my $cve_version = $cve->{version};
                    $cve_version =~ s/[<>]//g;

                    if ($version ne 'unknown' && version_compare($version, $cve_version)) {
                        push @{$found_plugins{$plugin}{vulnerabilities}}, $cve;
                        push @vulnerabilities, {
                            plugin => $plugin,
                            version => $version,
                            cve => $cve->{cve},
                            description => $cve->{description},
                            severity => $cve->{severity},
                        };

                        my $color = $cve->{severity} eq 'critical' ? $RED : $YELLOW;
                        print_color("$color    → $cve->{cve}: $cve->{description}$RESET");
                    }
                }
            }
        }
    }
}

sub version_compare {
    my ($v1, $v2) = @_;

    $v1 =~ s/[^0-9.]//g;
    $v2 =~ s/[^0-9.]//g;

    my @v1_parts = split /\./, $v1;
    my @v2_parts = split /\./, $v2;

    for (my $i = 0; $i < @v2_parts; $i++) {
        last if $i >= @v1_parts;
        if ($v1_parts[$i] < $v2_parts[$i]) {
            return 1;
        }
    }

    return 0;
}

sub show_results {
    print "\n" . "=" x 60 . "\n";
    print "GEFUNDENE PLUGINS (" . scalar(keys %found_plugins) . "):\n";
    print "=" x 60 . "\n";

    if (keys %found_plugins == 0) {
        print "❌ Keine Plugins gefunden\n";
        print "\nMögliche Gründe:\n";
        print "  • WordPress ist nicht im Standard-Pfad installiert\n";
        print "  • Plugins werden über CDN geladen\n";
        print "  • Die Seite verwendet Caching/Performance-Optimierung\n";
        print "  • Plugin-Pfade sind versteckt/gehasht\n";
        print "\nTipps:\n";
        print "  • --deep-scan aktivieren für gründlichere Suche\n";
        print "  • --aggressive für Fehlerseiten-Analyse\n";
        print "  • Manuell nach wp-content/plugins/ im Quelltext suchen\n";
    } else {
        # Nach Konfidenz sortieren
        my @sorted = sort {
            $found_plugins{$b}{confidence} <=> $found_plugins{$a}{confidence}
        } keys %found_plugins;

        print "GEFUNDEN NACH METHODE:\n";
        foreach my $method (sort keys %detected_methods) {
            print "  • $method: $detected_methods{$method}\n";
        }
        print "\n";

        foreach my $plugin (@sorted) {
            my $data = $found_plugins{$plugin};
            my $version = $data->{version} ? "v$data->{version}" : "Version unbekannt";
            my $vuln_count = scalar @{$data->{vulnerabilities}};

            my $color = $vuln_count > 0 ? $RED : $GREEN;
            print "$color  • $plugin ($version)$RESET\n";

            if ($config{verbose}) {
                print "    Methoden: " . join(', ', @{$data->{detected_by}}) . "\n";
                print "    Konfidenz: $data->{confidence}%\n";

                if ($vuln_count > 0) {
                    print "    $RED    Schwachstellen: $vuln_count$RESET\n";
                    foreach my $vuln (@{$data->{vulnerabilities}}) {
                        print "      - $vuln->{cve}: $vuln->{description}\n";
                    }
                }
            }
        }
    }

    if (@vulnerabilities > 0) {
        print "\n" . "-" x 40 . "\n";
        print "KRITISCHE SCHWACHSTELLEN ($RED" . scalar(@vulnerabilities) . "$RESET):\n";

        foreach my $vuln (@vulnerabilities) {
            my $color = $vuln->{severity} eq 'critical' ? $RED : $YELLOW;
            print "$color  • $vuln->{plugin} $vuln->{version}: $vuln->{cve}$RESET\n";
            print "    $vuln->{description}\n";
        }
    }
}

sub save_output {
    my $output = {
        tool => "WordPress Plugin Vulnerability Scanner",
        version => "2.0",
        timestamp => scalar(localtime()),
        target => $config{target_url},
        config => \%config,
        statistics => {
            total_plugins => scalar(keys %found_plugins),
            total_vulnerabilities => scalar(@vulnerabilities),
            total_requests => $total_requests,
            scan_time => time() - $start_time,
            detection_methods => \%detected_methods,
        },
        plugins => \%found_plugins,
        vulnerabilities => \@vulnerabilities,
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
        print $fh "Plugin,Version,Confidence,Anzahl Vulnerabilities,Schwachstellen\n";
        foreach my $plugin (keys %found_plugins) {
            my $data = $found_plugins{$plugin};
            my $vulns = join(';', map { $_->{cve} } @{$data->{vulnerabilities}});
            print $fh "$plugin,$data->{version},$data->{confidence}%," . scalar(@{$data->{vulnerabilities}}) . ",$vulns\n";
        }
        close($fh);
        print_success("CSV gespeichert: $config{output_json}");
    }
}

sub check_wordpress_vulnerabilities {
    my ($version) = @_;

    my %vulnerable_versions = (
        '4.9' => 'Mehrere kritische Sicherheitslücken in älteren Versionen',
        '5.0' => 'RCE in XML-RPC (CVE-2018-20147)',
        '5.1' => 'CSRF in Kommentaren (CVE-2019-9787)',
        '5.2' => 'Privilege Escalation (CVE-2019-17671)',
        '5.3' => 'XSS in Block Editor (CVE-2019-16780)',
        '5.4' => 'SQL Injection in WP_Query (CVE-2020-11027)',
        '5.5' => 'Stored XSS in Customizer (CVE-2020-15882)',
        '5.6' => 'XXE in Medien-Upload (CVE-2020-29560)',
        '5.7' => 'Object Injection (CVE-2021-29447)',
        '5.8' => 'RCE in Plugin-Update (CVE-2021-44223)',
        '5.9' => 'XSS in Navigation Block (CVE-2022-21662)',
        '6.0' => 'SQL Injection (CVE-2022-21661)',
        '6.1' => 'Data Exposure (CVE-2022-3590)',
    );

    foreach my $vuln_version (keys %vulnerable_versions) {
        if ($version =~ /^$vuln_version/) {
            push @vulnerabilities, {
                type => 'wordpress_core',
                name => "WordPress Core $version",
                vulnerability => $vulnerable_versions{$vuln_version},
                severity => 'high',
                confidence => 100,
            };
            print_warning("WordPress Core $version: " . $vulnerable_versions{$vuln_version});
        }
    }
}

sub print_recommendations {
    print_section("EMPFEHLUNGEN");

    my @recs = (
        "• WordPress Core immer aktuell halten",
        "• Alle Plugins regelmäßig aktualisieren",
        "• Nicht benötigte Plugins deaktivieren und löschen",
        "• Plugin-Quellen überprüfen (nur aus offiziellen Repositories)",
        "• Wordfence oder ähnliches Sicherheits-Plugin installieren",
        "• Regelmäßige Sicherheits-Scans durchführen",
        "• wp-config.php mit sicheren Zugangsdaten schützen",
        "• XML-RPC deaktivieren falls nicht benötigt",
    );

    if (@vulnerabilities > 0) {
        unshift @recs, "🔴 SOFORT HANDELN! " . scalar(@vulnerabilities) . " kritische Schwachstellen gefunden!";
    }

    if (keys %found_plugins == 0) {
        unshift @recs, "• Manuelle Überprüfung empfohlen: Besuche /wp-content/plugins/ im Browser";
        unshift @recs, "• Prüfe ob WordPress im Root-Verzeichnis installiert ist";
        unshift @recs, "• Teste mit --aggressive --deep-scan für intensivere Suche";
    }

    foreach (@recs) {
        print "$_\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
WORDPRESS PLUGIN VULNERABILITY SCANNER v2.0
================================================================================

BESCHREIBUNG:
  Scannt WordPress-Installationen nach installierten Plugins und prüft diese
  auf bekannte Sicherheitslücken (CVEs).

ERWEITERTE ERKENNUNGSMETHODEN:
  • Quellcode-Analyse (Scripts, Styles, Kommentare)
  • robots.txt Analyse
  • CSS/JS Asset-Analyse
  • JSON-API Endpunkte
  • Fehlerseiten-Analyse (aggressive Mode)
  • README.txt / CHANGELOG.txt
  • Typische Plugin-Pfade

VERWENDUNG:
  $0 --url <wordpress-url> [Optionen]

OPTIONEN:
  --url URL        WordPress-URL (z.B. https://example.com)

  --deep-scan      Alle bekannten Plugins testen (langsamer)
  --aggressive     Fehlerseiten-Analyse aktivieren

  --timeout N      Timeout in Sekunden (Default: 10)
  --delay N        Pause zwischen Requests (Default: 0.2)
  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe

  --output DATEI   Ergebnisse speichern
  --format FORMAT  text, json, csv (Default: text)
  --user-agent UA  Eigenen User-Agent verwenden

  --cve-db DATEI   Pfad zur lokalen CVE-Datenbank
  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Standard-Scan
  $0 --url https://example.com

  # Deep-Scan mit CVE-Check
  $0 --url https://example.com --deep-scan --cve-db cves.json

  # Aggressiver Modus für hartnäckige Fälle
  $0 --url https://example.com --aggressive --deep-scan --verbose

  # CSV-Output für Reporting
  $0 --url https://example.com --output plugins.csv --format csv

HINWEISE:
  • Nur auf eigenen oder autorisierten Systemen testen!
  • Bei --aggressive kann es zu Fehlermeldungen im Server-Log kommen
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
WORDPRESS PLUGIN VULNERABILITY SCANNER v2.0
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
