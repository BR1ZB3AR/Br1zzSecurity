/*
    Br1zz Security - rules applied to EVERY file, binaries included.

    Everything here must be cheap. These rules run against every shared library
    and executable on the system, so they use literal strings and fixed byte
    patterns only - no regular expressions. Text-oriented rules live in
    ../text/, which binaries never pay for.
*/

rule EICAR_Test_File
{
    meta:
        name        = "EICAR-Test-File"
        description = "EICAR standard anti-malware test file (harmless test signature)"
        severity    = "critical"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule Linux_CryptoMiner
{
    meta:
        name        = "Trojan.Linux.CoinMiner"
        description = "Cryptocurrency mining software or pool configuration"
        severity    = "high"

    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $x1    = "xmrig" nocase
        $x2    = "--donate-level" nocase
        $x3    = "cryptonight" nocase
        $x4    = "randomx" nocase
        $x5    = "nicehash" nocase
        $x6    = "minergate" nocase

    condition:
        any of ($pool*) or 2 of ($x*)
}

rule Linux_Shellcode_ExecveBinSh
{
    meta:
        name        = "Exploit.Linux.Shellcode.Execve"
        description = "x86/x86-64 execve(\"/bin/sh\") shellcode byte pattern"
        severity    = "critical"

    strings:
        $sc64_a = { 48 31 ?? 48 bb 2f 62 69 6e 2f 2f 73 68 }
        $sc64_b = { 48 bf 2f 62 69 6e 2f 2f 73 68 }
        $sc64_c = { 6a 3b 58 99 48 bb 2f 62 69 6e 2f 2f 73 68 }
        $sc32_a = { 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e }
        $sc32_b = { 6a 0b 58 99 52 66 68 2d 63 }

    condition:
        any of them
}

rule Linux_Rootkit_PreloadLibrary
{
    meta:
        name        = "Rootkit.Linux.LdPreload"
        description = "Userland rootkit library: resolves the real libc symbol and hides entries"
        severity    = "critical"

    strings:
        $preload = "/etc/ld.so.preload"
        $dlsym   = "dlsym"
        $rtld    = "RTLD_NEXT"
        $hook1   = "readdir64"
        $hook2   = "getdents64"
        $hook3   = "pam_authenticate"
        $hook4   = "unlink"

    condition:
        // A library that hooks libc *and* references the preload file. Loaders
        // and libc itself reference the path but do not hook through dlsym.
        $dlsym and $rtld and $preload and 2 of ($hook*)
}

rule Linux_Ransomware_Note
{
    meta:
        name        = "Ransom.Linux.Generic"
        description = "File-encrypting ransomware: ransom note paired with payment or marker extensions"
        severity    = "critical"

    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "all your files have been encrypted" nocase
        $note3 = "your files are encrypted" nocase
        $note4 = "READ_ME_TO_DECRYPT" nocase
        $note5 = "how to decrypt your files" nocase
        $pay1  = ".onion"
        $pay2  = "bitcoin" nocase
        $pay3  = "monero" nocase
        $ext1  = ".locked"
        $ext2  = ".encrypted"
        $ext3  = ".crypted"

    condition:
        any of ($note*) and (any of ($pay*) or any of ($ext*))
}
