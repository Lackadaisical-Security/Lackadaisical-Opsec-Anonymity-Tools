use strict;
use warnings;
use Getopt::Long;
use Net::MAC::Vendor;

# MAC Address Spoofer
# Part of Lackadaisical Anonymity Toolkit

my $VERSION = "1.0.0";

# OUI prefixes for common vendors
my %vendor_ouis = (
    'intel'     => ['00:1B:77', '00:1E:67', '00:23:14', '3C:A9:F4'],
    'realtek'   => ['00:E0:4C', '52:54:00', '00:07:32', '00:0A:CD'],
    'broadcom'  => ['00:10:18', '00:14:BF', '00:1A:A0', '00:1B:E9'],
    'atheros'   => ['00:03:7F', '00:13:74', '00:14:6C', '00:19:7D'],
    'apple'     => ['00:03:93', '00:0A:95', '00:0D:93', '00:14:51'],
    'cisco'     => ['00:00:0C', '00:01:42', '00:01:63', '00:01:96'],
    'dell'      => ['00:06:5B', '00:08:74', '00:0B:DB', '00:0D:56'],
    'hp'        => ['00:01:E6', '00:02:A5', '00:04:EA', '00:08:02'],
    'ibm'       => ['00:04:AC', '00:06:29', '00:09:6B', '00:0D:60'],
    'samsung'   => ['00:00:F0', '00:02:78', '00:07:AB', '00:09:18']
);

# Command line options
my $interface = '';
my $new_mac = '';
my $vendor = '';
my $random = 0;
my $restore = 0;
my $list = 0;
my $permanent = 0;
my $help = 0;
my $verbose = 0;

GetOptions(
    'interface|i=s' => \$interface,
    'mac|m=s'       => \$new_mac,
    'vendor|v=s'    => \$vendor,
    'random|r'      => \$random,
    'restore'       => \$restore,
    'list|l'        => \$list,
    'permanent|p'   => \$permanent,
    'help|h'        => \$help,
    'verbose'       => \$verbose
) or die("Error in command line arguments\n");

# Show help
if ($help) {
    show_help();
    exit 0;
}

# Detect OS
my $os = detect_os();
print "Detected OS: $os\n" if $verbose;

# List interfaces
if ($list) {
    list_interfaces();
    exit 0;
}

# Check if interface is specified
unless ($interface) {
    print "Error: Interface not specified. Use -i option.\n";
    show_help();
    exit 1;
}

# Check privileges
check_privileges();

# Get current MAC address
my $current_mac = get_current_mac($interface);
print "Current MAC: $current_mac\n" if $current_mac && $verbose;

# Save original MAC for restoration
save_original_mac($interface, $current_mac) if $current_mac && !$restore;

# Perform requested action
if ($restore) {
    restore_original_mac($interface);
} elsif ($new_mac) {
    validate_mac($new_mac) or die "Invalid MAC address format\n";
    change_mac($interface, $new_mac);
} elsif ($vendor) {
    my $vendor_mac = generate_vendor_mac($vendor);
    change_mac($interface, $vendor_mac);
} elsif ($random) {
    my $random_mac = generate_random_mac();
    change_mac($interface, $random_mac);
} else {
    print "Error: No action specified\n";
    show_help();
    exit 1;
}

# Subroutines

sub show_help {
    print <<'EOH';
MAC Address Spoofer v$VERSION
Part of Lackadaisical Anonymity Toolkit

Usage: mac_spoofer.pl -i INTERFACE [OPTIONS]

Options:
  -i, --interface IFACE    Network interface to modify
  -m, --mac MAC           Set specific MAC address
  -v, --vendor VENDOR     Generate MAC from vendor OUI
  -r, --random            Generate random MAC address
  --restore               Restore original MAC address
  -l, --list              List network interfaces
  -p, --permanent         Make change permanent (survives reboot)
  --verbose               Verbose output
  -h, --help              Show this help

Examples:
  mac_spoofer.pl -i eth0 -r                    # Random MAC on eth0
  mac_spoofer.pl -i wlan0 -v intel            # Intel vendor MAC
  mac_spoofer.pl -i eth0 -m 00:11:22:33:44:55 # Specific MAC
  mac_spoofer.pl -i eth0 --restore            # Restore original

Supported vendors: intel, realtek, broadcom, atheros, apple, cisco, dell, hp, ibm, samsung
EOH
}

sub detect_os {
    if ($^O eq 'linux') {
        return 'linux';
    } elsif ($^O eq 'darwin') {
        return 'macos';
    } elsif ($^O eq 'MSWin32') {
        return 'windows';
    } elsif ($^O =~ /bsd/i) {
        return 'bsd';
    } else {
        return 'unknown';
    }
}

sub check_privileges {
    if ($os eq 'linux' || $os eq 'macos' || $os eq 'bsd') {
        die "Error: Root privileges required\n" unless $< == 0;
    } elsif ($os eq 'windows') {
        # Check for admin on Windows
        my $admin_check = `net session 2>&1`;
        die "Error: Administrator privileges required\n" if $?
    }
}

sub list_interfaces {
    print "Available network interfaces:\n\n";
    
    if ($os eq 'linux') {
        my @interfaces = `ip link show | grep -E '^[0-9]+:' | cut -d: -f2`;
        foreach my $iface (@interfaces) {
            chomp $iface;
            $iface =~ s/^\s+|\s+$//g;
            next if $iface eq 'lo';
            
            my $mac = get_current_mac($iface);
            print "  $iface";
            print " ($mac)" if $mac;
            print "\n";
        }
    } elsif ($os eq 'macos') {
        my @interfaces = `ifconfig -l`;
        chomp @interfaces;
        my @ifaces = split /\s+/, $interfaces[0];
        
        foreach my $iface (@ifaces) {
            next if $iface eq 'lo0';
            my $mac = get_current_mac($iface);
            print "  $iface";
            print " ($mac)" if $mac;
            print "\n";
        }
    } elsif ($os eq 'windows') {
        my @interfaces = `wmic nic get name,macaddress,netenabled /format:csv 2>nul`;
        shift @interfaces; # Remove header
        shift @interfaces; # Remove empty line
        
        foreach my $line (@interfaces) {
            chomp $line;
            next unless $line;
            my @parts = split /,/, $line;
            next unless $parts[2] && $parts[2] eq 'TRUE';
            print "  $parts[3] ($parts[1])\n" if $parts[1];
        }
    }
}

sub get_current_mac {
    my ($interface) = @_;
    
    if ($os eq 'linux') {
        my $output = `ip link show $interface 2>/dev/null | grep link/ether`;
        if ($output =~ /link\/ether\s+([0-9a-fA-F:]+)/) {
            return uc($1);
        }
    } elsif ($os eq 'macos') {
        my $output = `ifconfig $interface 2>/dev/null | grep ether`;
        if ($output =~ /ether\s+([0-9a-fA-F:]+)/) {
            return uc($1);
        }
    } elsif ($os eq 'windows') {
        my $output = `wmic nic where "name like '%$interface%'" get macaddress /value 2>nul`;
        if ($output =~ /MACAddress=([0-9A-F:]+)/i) {
            return uc($1);
        }
    }
    
    return undef;
}

sub validate_mac {
    my ($mac) = @_;
    return $mac =~ /^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$/;
}

sub generate_random_mac {
    # Generate random MAC with locally administered bit set
    my @octets;
    
    # First octet: set locally administered bit (bit 1)
    push @octets, sprintf("%02X", (int(rand(256)) & 0xFC) | 0x02);
    
    # Remaining octets
    for (my $i = 1; $i < 6; $i++) {
        push @octets, sprintf("%02X", int(rand(256)));
    }
    
    return join(':', @octets);
}

sub generate_vendor_mac {
    my ($vendor) = @_;
    
    $vendor = lc($vendor);
    unless (exists $vendor_ouis{$vendor}) {
        die "Unknown vendor: $vendor\n";
    }
    
    # Select random OUI from vendor
    my $ouis = $vendor_ouis{$vendor};
    my $oui = $ouis->[int(rand(@$ouis))];
    
    # Generate random last 3 octets
    my @octets = split /:/, $oui;
    for (my $i = 3; $i < 6; $i++) {
        push @octets, sprintf("%02X", int(rand(256)));
    }
    
    return join(':', @octets);
}

sub change_mac {
    my ($interface, $mac) = @_;
    
    print "Changing MAC address of $interface to $mac\n";
    
    if ($os eq 'linux') {
        system("ip link set dev $interface down") == 0 
            or die "Failed to bring interface down\n";
        
        system("ip link set dev $interface address $mac") == 0
            or die "Failed to set MAC address\n";
        
        system("ip link set dev $interface up") == 0
            or die "Failed to bring interface up\n";
        
    } elsif ($os eq 'macos') {
        system("sudo ifconfig $interface ether $mac") == 0
            or die "Failed to set MAC address\n";
            
    } elsif ($os eq 'windows') {
        # Windows requires registry modification
        my $reg_path = find_windows_adapter_reg($interface);
        if ($reg_path) {
            my $clean_mac = $mac;
            $clean_mac =~ s/://g;
            
            system("reg add \"$reg_path\" /v NetworkAddress /t REG_SZ /d $clean_mac /f >nul 2>&1") == 0
                or die "Failed to set MAC address in registry\n";
            
            # Restart adapter
            system("wmic path win32_networkadapter where \"name like '%$interface%'\" call disable >nul 2>&1");
            sleep(2);
            system("wmic path win32_networkadapter where \"name like '%$interface%'\" call enable >nul 2>&1");
        } else {
            die "Could not find adapter in registry\n";
        }
    }
    
    # Verify change
    sleep(2);
    my $new_mac = get_current_mac($interface);
    if ($new_mac && uc($new_mac) eq uc($mac)) {
        print "MAC address successfully changed to $mac\n";
    } else {
        print "Warning: MAC address change may have failed\n";
        print "Current MAC: $new_mac\n" if $new_mac;
    }
}

sub save_original_mac {
    my ($interface, $mac) = @_;
    
    my $save_dir = $ENV{'HOME'} || $ENV{'USERPROFILE'} || '/tmp';
    my $save_file = "$save_dir/.mac_original_$interface";
    
    open(my $fh, '>', $save_file) or return;
    print $fh $mac;
    close($fh);
}

sub restore_original_mac {
    my ($interface) = @_;
    
    my $save_dir = $ENV{'HOME'} || $ENV{'USERPROFILE'} || '/tmp';
    my $save_file = "$save_dir/.mac_original_$interface";
    
    unless (-f $save_file) {
        die "No saved MAC address found for $interface\n";
    }
    
    open(my $fh, '<', $save_file) or die "Cannot read saved MAC\n";
    my $original_mac = <$fh>;
    close($fh);
    chomp($original_mac);
    
    print "Restoring original MAC address: $original_mac\n";
    change_mac($interface, $original_mac);
    
    unlink($save_file);
}

sub find_windows_adapter_reg {
    my ($interface) = @_;
    
    my @reg_output = `reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318} /s /f "$interface" 2>nul`;
    
    foreach my $line (@reg_output) {
        if ($line =~ /HKEY_LOCAL_MACHINE\\(.+)/) {
            my $path = "HKLM\\$1";
            # Verify this is the right adapter
            my $desc = `reg query "$path" /v DriverDesc 2>nul`;
            if ($desc =~ /$interface/i) {
                return $path;
            }
        }
    }
    
    return undef;
}

# Handle signals for cleanup
$SIG{INT} = sub {
    print "\nInterrupted. MAC address changes remain in effect.\n";
    exit 1;
};