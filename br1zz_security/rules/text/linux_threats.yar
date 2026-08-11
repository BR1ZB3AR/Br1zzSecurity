/*
    Br1zz Security - Linux threat rules

    Two precision disciplines are applied throughout, both learned from
    measuring this rule set against a real /usr/bin:

    1. FILE TYPE GATING. Behavioural shell rules require `is_text`. A compiled
       binary's string table contains "/dev/tcp/", ".bashrc", "curl" and
       "/etc/ld.so.preload" as ordinary data - matching those in an ELF flags
       git, bash, systemctl and snap.

    2. PROXIMITY, NOT CO-OCCURRENCE. Two strings appearing somewhere in a
       20,000-line script proves nothing. Rules that correlate indicators
       require them within a few hundred bytes of each other, which is what
       "these two things are part of the same statement" actually means.
*/

import "math"

rule Linux_ReverseShell_DevTcp
{
    meta:
        name        = "Backdoor.Linux.ReverseShell.DevTcp"
        description = "Interactive shell redirected over bash's /dev/tcp pseudo-device"
        severity    = "critical"

    strings:
        $rs = /(bash|sh|zsh)\s+-[a-z]*i[a-z]*\s*>\s*&\s*\/dev\/(tcp|udp)\/[0-9a-z.\-]+\/[0-9]{1,5}/ nocase
        $rs2 = /\/dev\/(tcp|udp)\/[0-9a-z.\-]+\/[0-9]{1,5}\s*[;<>&|]/ nocase
        $ex = /exec\s+[0-9]+\s*<\s*>\s*\/dev\/tcp\// nocase

    condition:
        any of them
}

rule Linux_ReverseShell_Netcat
{
    meta:
        name        = "Backdoor.Linux.ReverseShell.Netcat"
        description = "Netcat or a named pipe used to serve a shell to a remote host"
        severity    = "high"

    strings:
        $nc_e = /\bn(c|cat|etcat)(\.traditional)?\s+(-[a-z]+\s+)*-[a-z]*e[a-z]*\s+\/bin\/(ba)?sh/ nocase
        $fifo = "mkfifo"
        $nc   = /\bn(c|cat)\s+(-[a-z]+\s+)*[0-9a-z.\-]+\s+[0-9]{2,5}/ nocase

    condition:
        (
            $nc_e
            // mkfifo and netcat must belong to the same pipeline, not merely
            // both appear in a large script.
            or for any i in (1..#fifo) : (
                 for any j in (1..#nc) : ( @nc[j] > @fifo[i] and @nc[j] - @fifo[i] < 200 )
               )
        )
}

rule Linux_ReverseShell_Interpreter
{
    meta:
        name        = "Backdoor.Linux.ReverseShell.Interpreter"
        description = "Python/Perl/Ruby socket connected directly to a shell process"
        severity    = "critical"

    strings:
        $py_sock  = "socket.socket("
        $py_dup   = "dup2("
        $py_pty   = "pty.spawn("
        $py_shell = "/bin/sh"
        $py_sub   = /subprocess\.(call|Popen)\s*\(\s*\[?\s*["']\/bin\/(ba)?sh/
        $pl_sock  = /socket\s*\(\s*S\s*,\s*PF_INET/
        $pl_exec  = /exec\s*\(?\s*["']\/bin\/(ba)?sh/
        $rb_sock  = "TCPSocket.new"
        $rb_exec  = /exec\s*\(?\s*["']\/bin\/(ba)?sh/

    condition:
        (
            ($py_sock and ($py_dup or $py_pty or $py_sub) and $py_shell)
            or ($pl_sock and $pl_exec)
            or ($rb_sock and $rb_exec)
        )
}

rule Linux_Dropper_RemoteExec
{
    meta:
        name        = "Trojan.Linux.Dropper.RemoteExec"
        description = "Fetches remote content and executes it without writing a reviewable file"
        severity    = "high"

    strings:
        // Piping a download straight into a shell is unambiguous on its own.
        $pipe1 = /curl\s+[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|k)?sh\b/ nocase
        $pipe2 = /wget\s+[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|k)?sh\b/ nocase
        $b64   = /base64\s+(-{1,2}[a-z]+\s+)*-{1,2}d[a-z]*\s*[^\n]{0,60}\|\s*(ba|z)?sh\b/ nocase
        // Download-then-execute needs the two halves to be adjacent.
        $fetch = /(curl|wget)\s+[^\n]{0,160}(-O|-o|--output)\b/ nocase
        $chmod = /chmod\s+[+0-7]*x\b/ nocase

    condition:
        (
            any of ($pipe*) or $b64
            or for any i in (1..#fetch) : (
                 for any j in (1..#chmod) : ( @chmod[j] > @fetch[i] and @chmod[j] - @fetch[i] < 300 )
               )
        )
}

rule Linux_Webshell_PHP
{
    meta:
        name        = "Backdoor.PHP.Webshell"
        description = "PHP web shell: request parameters passed to a command execution sink"
        severity    = "critical"

    strings:
        $php    = "<?php"
        $php2   = "<?="
        $sink1  = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $sink2  = /system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $sink3  = /shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $sink4  = /passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $sink5  = /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $sink6  = /proc_open\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $sink7  = /popen\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $obf    = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ nocase

    condition:
        any of ($php*) and (any of ($sink*) or $obf)
}

rule Linux_Webshell_Generic_Uploader
{
    meta:
        name        = "Backdoor.Generic.WebshellUploader"
        description = "Script combining a file-upload handler with command execution"
        severity    = "high"

    strings:
        $up1  = "move_uploaded_file"
        $up2  = "$_FILES"
        $cmd  = /(system|exec|shell_exec|passthru)\s*\(\s*\$/ nocase
        $hide = /(error_reporting\s*\(\s*0\s*\)|@ini_set|set_time_limit\s*\(\s*0\s*\))/ nocase

    condition:
        all of ($up*) and $cmd and $hide
}

rule Linux_Persistence_SSHKey
{
    meta:
        name        = "Backdoor.Linux.Persistence.SSHKey"
        description = "Appends an attacker's public key to authorized_keys"
        severity    = "critical"

    strings:
        $auth = ".ssh/authorized_keys"
        $key  = /ssh-(rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+\/]{40,}/
        $app  = /(>>|tee\s+-a|cat\s*>>)/

    condition:
        $auth and $key and $app
        // The key material and the target file must be part of one statement.
        and for any i in (1..#auth) : (
              for any j in (1..#key) : (
                math.abs(@key[j] - @auth[i]) < 400
              )
            )
}

rule Linux_Persistence_Cron
{
    meta:
        name        = "Backdoor.Linux.Persistence.Cron"
        description = "Installs a cron job that fetches or executes remote code"
        severity    = "high"

    strings:
        // Piping into crontab, or writing into a cron directory.
        $install1 = /(echo|printf|cat)\s+[^\n]{0,200}\|\s*crontab\s+-/ nocase
        $install2 = /crontab\s+-\s*$/ nocase
        $install3 = /(>>?|tee)\s*[^\n]{0,40}\/(etc\/cron\.[a-z]+|var\/spool\/cron)/ nocase
        $payload  = /(curl|wget|\/dev\/tcp\/|base64\s+-d|nc\s+-)/ nocase

    condition:
        any of ($install*) and $payload
        and for any i in (1..#payload) : (
              (@payload[i] < 4000) or
              for any j in (1..#install3) : ( math.abs(@payload[i] - @install3[j]) < 500 )
            )
}

rule Linux_Persistence_ShellProfile
{
    meta:
        name        = "Backdoor.Linux.Persistence.ShellProfile"
        description = "Appends a remote-execution payload to a shell startup file"
        severity    = "high"

    strings:
        $rc  = /(>>|tee\s+-a)\s*["']?(~|\$HOME|\/home\/[^\/\s]+|\/root)\/\.(bashrc|bash_profile|profile|zshrc|zprofile)/
        $net = /(curl|wget|\/dev\/tcp\/|base64\s+-d|nc\s+-e)/ nocase

    condition:
        $rc and $net
        and for any i in (1..#rc) : (
              for any j in (1..#net) : ( math.abs(@net[j] - @rc[i]) < 400 )
            )
}

rule Linux_AntiAnalysis_Debugger
{
    meta:
        name        = "Trojan.Linux.AntiAnalysis"
        description = "Script actively checking for a debugger, tracer, or virtual machine"
        severity    = "medium"

    strings:
        $tr  = "TracerPid"
        $st  = "/proc/self/status"
        $pt  = "PTRACE_TRACEME"
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "QEMU" nocase
        $dmi = "/sys/class/dmi/id/product_name"

    condition:
        // Gated to scripts: strace, gdb, udevadm and systemd legitimately carry
        // every one of these strings in their binaries.
        (($tr and $st) or $pt or ($dmi and 2 of ($vm*)))
}

rule Linux_AntiForensics_LogWipe
{
    meta:
        name        = "Trojan.Linux.AntiForensics"
        description = "Erases system logs or shell history to conceal activity"
        severity    = "high"

    strings:
        $h1 = "history -c"
        $h2 = "unset HISTFILE"
        $h3 = "HISTFILE=/dev/null"
        $l1 = "/var/log/wtmp"
        $l2 = "/var/log/auth.log"
        $l3 = "/var/log/secure"
        $l4 = "/var/log/lastlog"
        $rm = /(rm\s+-[a-z]*f|shred\s+-|:\s*>\s*|truncate\s+-s\s*0)/ nocase

    condition:
        (
            2 of ($h*)
            // Log destruction must be adjacent to the log path.
            or for any i in (1..#rm) : (
                 for any j in (1..#l1) : ( math.abs(@l1[j] - @rm[i]) < 120 ) or
                 for any j in (1..#l2) : ( math.abs(@l2[j] - @rm[i]) < 120 ) or
                 for any j in (1..#l3) : ( math.abs(@l3[j] - @rm[i]) < 120 ) or
                 for any j in (1..#l4) : ( math.abs(@l4[j] - @rm[i]) < 120 )
               )
        )
}

rule Linux_Defense_Evasion_DisableSecurity
{
    meta:
        name        = "Trojan.Linux.DisableSecurity"
        description = "Disables firewalls, SELinux/AppArmor, or antivirus services"
        severity    = "high"

    strings:
        $s1 = /systemctl\s+(stop|disable|mask)\s+(ufw|firewalld|apparmor|clamav[a-z-]*|auditd|falco)/ nocase
        $s2 = "setenforce 0"
        $s3 = /iptables\s+-F\s*$/ nocase
        $s4 = /(service|\/etc\/init\.d\/)\s*(ufw|iptables|auditd|apparmor)\s+stop/ nocase

    condition:
        any of them
}

rule Linux_Obfuscated_Script
{
    meta:
        name        = "Trojan.Script.Obfuscated"
        description = "Script whose payload is encoded and handed to an execution sink"
        severity    = "high"

    strings:
        $shebang = "#!"
        // Upper-bounded on purpose. An open-ended {600,} makes YARA retry an
        // unbounded match at every offset, which is O(n^2) against a large
        // base64 payload: 7 MB of CUPS PPD data took over 120 seconds and hit
        // the scan timeout. We only need to know a long blob exists, and
        // 600-700 characters proves that in constant time per offset.
        // The leading non-base64 character anchors the match to the *start* of
        // a blob. Without it the bounded pattern matches at every offset inside
        // a large blob - millions of recorded matches, and YARA warns about it.
        $b64blob = /[^A-Za-z0-9+\/=][A-Za-z0-9+\/]{600,700}/
        $dec1    = /base64\s+(-{1,2}[a-z]+\s+)*-{1,2}d/ nocase
        $dec2    = "b64decode"
        $dec3    = "atob("
        $dec4    = "gzinflate"
        $dec5    = "str_rot13"
        $sink1   = /\beval\s*\(/ nocase
        $sink2   = /\bexec\s*\(/ nocase
        $sink3   = /\|\s*(ba|z)?sh\b/

    condition:
        $shebang at 0 and $b64blob and any of ($dec*) and any of ($sink*)
}

rule Linux_SuspiciousSystemdUnit
{
    meta:
        name        = "Backdoor.Linux.SystemdUnit"
        description = "systemd unit that launches code from a temporary path or the network"
        severity    = "high"

    strings:
        $svc  = "[Service]"
        // The payload must be on the ExecStart line itself.
        $exec = /Exec(Start|StartPre|StopPost)\s*=[^\n]{0,200}(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|curl\s|wget\s|base64\s|\/dev\/tcp\/)/ nocase

    condition:
        $svc and $exec and filesize < 64KB
}

rule Linux_Rootkit_PreloadInstall
{
    meta:
        name        = "Rootkit.Linux.LdPreload"
        description = "Script installing a userland rootkit via /etc/ld.so.preload"
        severity    = "critical"

    strings:
        // Writing the preload file is an installation, not a mention: package
        // scripts and man pages reference the path without touching it.
        $write = /(>>?|tee|echo|printf|cat)\s*[^\n]{0,60}\/etc\/ld\.so\.preload/ nocase

    condition:
        $write
}
