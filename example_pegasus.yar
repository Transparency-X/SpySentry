// YARA Rule for Detecting Pegasus Spyware
// Author: Transparency-X
// Date: 2026-06-01
// Reference: SpySentry Project v1.0
// Description: Detects Pegasus spyware based on known strings, hashes, and patterns.
// Severity: High

rule Detect_Pegasus_Spyware {
    meta:
        description = "Detects Pegasus spyware by known strings and patterns"
        author = "Transparency-X"
        date = "2026-06-01"
        reference = "SpySentry Project v1.0"
        severity = "high"
        category = "spyware"
        family = "Pegasus"
        os = "iOS, Android"
        version = "1.0"

    strings:
        // Known Pegasus strings
        $pegasus_string_1 = "Pegasus" wide ascii
        $pegasus_string_2 = "NSO Group" wide ascii
        $pegasus_string_3 = "Trident" wide ascii
        
        // Known Pegasus file paths
        $pegasus_path_1 = "/var/mobile/Library/Preferences/com.apple.Pegasus.plist" nocase wide
        $pegasus_path_2 = "/data/data/com.apple.Pegasus/" nocase wide
        
        // Known Pegasus registry keys (Windows)
        $pegasus_reg_1 = "SOFTWARE\\Pegasus" nocase wide
        $pegasus_reg_2 = "SOFTWARE\\NSO Group\\Pegasus" nocase wide
        
        // Known Pegasus mutex names
        $pegasus_mutex_1 = "Global\\PegasusMutex" nocase wide
        $pegasus_mutex_2 = "NSO_Pegasus_2026" nocase wide
        
        // Known Pegasus C2 IPs (replace with actual IPs)
        $c2_ip_1 = "192.168.1.100" nocase
        $c2_ip_2 = "10.0.0.50" nocase
        
        // Known Pegasus domains (replace with actual domains)
        $c2_domain_1 = "pegasus-c2-server.com" nocase
        $c2_domain_2 = "nso-group.net" nocase
        
        // Known Pegasus hashes (replace with actual hashes)
        $pegasus_hash_1 = { 6A 40 68 00 30 00 00 FF D5 8B 45 3C 10 8B 45 38 FF D0 }
        $pegasus_hash_2 = { 8D 45 F4 50 8D 45 F0 50 FF 75 08 8D 45 E8 50 }

    condition:
        // Main condition: At least 2 strings must match
        uint16(0) == 0x5A4D or  // PE header signature (MZ)
        (
            (uint32(0) == 0xFE646172) or  // Mach-O magic number (for iOS)
            (uint32(0) == 0xCEFAEDFE) or  // Mach-O magic number (for iOS, big-endian)
            (uint32(0) == 0x7F454C46)     // ELF magic number (for Android/Linux)
        ) or
        (
            2 of ($pegasus_*) or
            1 of ($c2_*) or
            1 of ($pegasus_hash_*)
        )
}

// Rule for Pegasus iOS variant
rule Detect_Pegasus_iOS {
    meta:
        description = "Detects Pegasus spyware specifically targeting iOS devices"
        author = "Transparency-X"
        date = "2026-06-01"
        reference = "SpySentry Project v1.0"
        severity = "high"
        category = "spyware"
        family = "Pegasus"
        os = "iOS"

    strings:
        $ios_pegasus_1 = "com.apple.Pegasus" nocase wide
        $ios_pegasus_2 = "NSOiOS" nocase wide
        $ios_pegasus_3 = "/private/var/mobile/Library/Pegasus/" nocase wide
        
        // Known iOS Pegasus entitlements
        $ios_entitlement_1 = "platform-application" nocase wide
        $ios_entitlement_2 = "com.apple.developer.core-services" nocase wide

    condition:
        uint32(0) == 0xFE646172 or  // Mach-O magic number
        uint32(0) == 0xCEFAEDFE or  // Mach-O magic number (big-endian)
        2 of ($ios_*)
}

// Rule for Pegasus Android variant
rule Detect_Pegasus_Android {
    meta:
        description = "Detects Pegasus spyware specifically targeting Android devices"
        author = "Transparency-X"
        date = "2026-06-01"
        reference = "SpySentry Project v1.0"
        severity = "high"
        category = "spyware"
        family = "Pegasus"
        os = "Android"

    strings:
        $android_pegasus_1 = "com.nso.pegasus" nocase wide
        $android_pegasus_2 = "/data/data/com.nso.pegasus/" nocase wide
        $android_pegasus_3 = "PegasusService" nocase wide

    condition:
        uint32(0) == 0x7F454C46 or  // ELF magic number
        2 of ($android_*)
}

// Rule for Pegasus C2 traffic
rule Detect_Pegasus_C2_Traffic {
    meta:
        description = "Detects network traffic to known Pegasus C2 servers"
        author = "Transparency-X"
        date = "2026-06-01"
        reference = "SpySentry Project v1.0"
        severity = "high"
        category = "c2_traffic"
        family = "Pegasus"

    strings:
        // Known Pegasus C2 IPs (replace with actual IPs)
        $c2_ip_1 = "192.168.1.100"
        $c2_ip_2 = "10.0.0.50"
        $c2_ip_3 = "203.0.113.45"
        
        // Known Pegasus C2 domains (replace with actual domains)
        $c2_domain_1 = "pegasus-c2-server.com"
        $c2_domain_2 = "nso-group.net"
        $c2_domain_3 = "c2.pegasus.example"
        
        // Known Pegasus user agents
        $pegasus_ua_1 = "PegasusClient/1.0"
        $pegasus_ua_2 = "NSO-Group-Agent"

    condition:
        any of them
}

// Rule for Pegasus persistence mechanisms
rule Detect_Pegasus_Persistence {
    meta:
        description = "Detects Pegasus persistence mechanisms on infected systems"
        author = "Transparency-X"
        date = "2026-06-01"
        reference = "SpySentry Project v1.0"
        severity = "high"
        category = "persistence"
        family = "Pegasus"

    strings:
        // Known Pegasus persistence files
        $persistence_file_1 = "PegasusAgent.plist" nocase wide
        $persistence_file_2 = "com.nso.pegasus.agent" nocase wide
        
        // Known Pegasus cron jobs
        $persistence_cron_1 = "* * * * * /var/mobile/Library/Pegasus/agent" nocase wide
        $persistence_cron_2 = "@reboot /data/data/com.nso.pegasus/service" nocase wide
        
        // Known Pegasus launch agents/daemons (macOS)
        $launch_agent_1 = "com.nso.pegasus.agent.plist" nocase wide
        $launch_daemon_1 = "com.nso.pegasus.daemon.plist" nocase wide

    condition:
        any of them
}
