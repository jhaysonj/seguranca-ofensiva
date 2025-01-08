a



# http
- http 1.1 requer Host no cabeçalho
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
ftp 192.168.0.8 -P 21
```
comandos úteis:
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

## ftp (passivo x ativo)
referencial é o servidor
- No modo FTP passivo o servidor fica escutando enquanto aguarda a conexão do cliente. 
- No modo FTP ativo, o cliente fica escutando enquanto aguarda a conexão do servidor.

Modo Passivo:
    No modo passivo, o cliente estabelece tanto a conexão de controle (porta 21) quanto a conexão de dados. Após estabelecer a conexão de controle, o cliente solicita ao servidor uma porta para a conexão de dados. O servidor então informa ao cliente qual porta ele (o servidor) está escutando para a conexão de dados (geralmente uma porta acima de 1023). O cliente, então, abre uma conexão para essa porta no servidor.

Modo Ativo:
    No modo ativo, o cliente estabelece a conexão de controle com o servidor na porta 21. Quando é necessário transferir dados, o cliente informa ao servidor qual porta ele (o cliente) está escutando para a conexão de dados (normalmente uma porta acima de 1023). O servidor então abre uma conexão a partir de sua porta 20 para a porta especificada pelo cliente.



# NetBios (139/tcp)   / SMB (445/tcp)
Permite o compartilhamento de arquivos/diretórios na rede.


NetBios (porta 139) --> antigo
SMB (porta 445) --> mais recente

protocolos aceitos pelo SMB
```
nmap --script smb-protocols -p 445 10.10.11.35 -Pn
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

```

estabelece conexão passando usuário e senha
```
smbclient  \\\\10.10.11.35\\SYSVOL\\ -U "user%pass" 
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


Comandos Úteis:
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

## via windows
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

# rpc (Remote Procedure Call)  135/tcp
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

# SMTP
O SMTP (Simple Mail Transfer Protocol) é um protocolo de comunicação utilizado para enviar e transferir e-mails entre servidores de e-mail e clientes.
**porta default: 25**
```
nc -v <ip> <porta>
```

ex de resposta quando o usuário existe
```
EHLO root
250 2.1.5 OK
```

ex de resposta quando o usuário não existe
```
EHLO jhayson
550 5.1.1 User unknown
```

ex de resposta quando o usuário existe
```
VRFY root
250 2.1.5 OK
```

```
VRFY www-data
250 2.1.5 OK
```

ex de resposta quando o usuário não existe
```
VRFY jhayson
550 5.1.1 User unknown
```

obs: podemos enviar um email para um determinador usuário para enumerar se o usuário em questão existe ou não. De acordo com a resposta recebida podemos definir se o usuário existe ou não.

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

# ssh (secure shell)
Permite conexão de shell remota
Portas default: 22, 2222, 22222

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

# wordpress
```
wpscan --url http://blog.thm --enumerate ap,at,dbe,cb,u --detection-mode aggressive
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
wpscan --url http://blog.thm/ --usernames kwheel,bjoel --passwords ~/wordlist/rockyou.txt
```
http://blog.thm/xmlrpc.php
	XML-RPC server accepts POST requests only.


arquivo de configuração:
contem informações úteis do banco de dados
```
cat wp-config.php


// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'blog');


/** MySQL database username */
define('DB_USER', 'wordpressuser');

/** MySQL database password */
define('DB_PASSWORD', 'LittleYellowLamp90!@');

```

# msfconsole
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
reg save hklm\sam <name>
reg save hklm\system <name>
impacket-secretsdump -sam <sam> -system <system> LOCAL
```

**versões de hash no windows (mais antigos pro mais recentes)**
- LM (geralmente termina com `EE`, se  começar com `AA` e terminar com `EE` está em desuso)
- NTLM = NTLM V1
- NTLM V2
obs: se for windows antigo, testar eternalblue

**Path for hashes:**
- C:\Windows\system32\config\SAM                        usuarios windows 7,8,10,11
- C:\Windows\system32\NTDS\ntds.dit                    usuarios do windows server
- C:\Windows\system32\config\SYSTEM                 usuarios windows 7,8,10,11

**Cracking hashes:**
```
john --format=nt --wordlist=<wordlist> <hashfile>
john --format=lm --wordlist=<wordlist> <hashfile>
```

**hashes da RAM:**
- /usr/share/windows-binaries/fgdump/fgdump.exe
- /usr/share/windows-resources/wce/wce-universal.exe

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

## Remote Desktop Protocol (rdp)
utilitário para interagir com rdp no linux
```
xfreerdp
xfreerdp /v:<IP_do_host> /u:<nome_do_usuário> /p:<senha>
xfreerdp /v:10.10.39.3 /u:Administrator /p:letmein123!
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

Flags úteis:
-s PORT: porta do serviço
-L: path para lista de usuários
-P: path para lista de senhas
-C: path para arquivo no formato "login:pass"
-l: usuário em texto
-p: senha em texto


# gobuster
```
gobuster -u http://10.10.206.2 -w ~/wordlist/SecLists/Discovery/Web-Content/raft-large-directories.txt -t 100 -e 
```
-e printa a url toda
-t numero de threads
-u url
-x string              File extension(s) to search for (dir mode only)
-p string              Proxy to use for requests [http(s)://host:port] (dir mode only)

# ffuf
bruteforce de +1 parametro
```
ffuf -w users.txt:USER -w passwords.txt:PASS -u http://blog.thm/wp-login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "log=USER&pwd=PASS&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1"
```

proxy burp `-x`
```
-x http://127.0.0.1:8080
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

# hashcat

```
hashcat -m <hash_type> -a <attack_mode> <hash_file> <wordlist>
```
via de regra eu quero o `-a 0` (ataque de dicionario)
## Modos de Ataque (`-a`)

1. **Ataque de Dicionário (`-a 0`)**
    
    - **Descrição:** Tenta quebrar o hash comparando-o com palavras em uma lista de palavras (wordlist).
    - **Uso:** `hashcat -m <hash_type> -a 0 <hash_file> <wordlist>`
    - **Exemplo:** `hashcat -m 0 -a 0 hashes.txt rockyou.txt`
2. **Ataque de Combinado (`-a 1`)**
    
    - **Descrição:** Combina cada palavra de duas listas de palavras e tenta quebrar o hash.
    - **Uso:** `hashcat -m <hash_type> -a 1 <hash_file> <wordlist1> <wordlist2>`
    - **Exemplo:** `hashcat -m 0 -a 1 hashes.txt list1.txt list2.txt`
3. **Ataque de Regras (`-a 3`)**
    
    - **Descrição:** Utiliza uma série de regras para modificar cada entrada de uma wordlist. Por exemplo, pode adicionar números ao final, substituir letras, etc.
    - **Uso:** `hashcat -m <hash_type> -a 0 <hash_file> <wordlist> --rules <rules_file>`
    - **Exemplo:** `hashcat -m 0 -a 0 hashes.txt rockyou.txt --rules dive.rule`
4. **Ataque de Máscara (`-a 3`)**
    
    - **Descrição:** Gera palavras-chave dinamicamente com base em uma máscara, útil para realizar ataques de força bruta.
    - **Uso:** `hashcat -m <hash_type> -a 3 <hash_file> <mask>`
    - **Exemplo:** `hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?l?l`
5. **Ataque de Toggle-Case (`-a 4`)**
    
    - **Descrição:** Alterna a caixa (maiúsculas e minúsculas) das palavras da wordlist.
    - **Uso:** `hashcat -m <hash_type> -a 4 <hash_file> <wordlist>`
    - **Exemplo:** `hashcat -m 0 -a 4 hashes.txt rockyou.txt`
6. **Ataque de Mask-Generated (`-a 6`)**
    
    - **Descrição:** Utiliza uma wordlist e aplica uma máscara ao final de cada palavra.
    - **Uso:** `hashcat -m <hash_type> -a 6 <hash_file> <wordlist> <mask>`
    - **Exemplo:** `hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d`
7. **Ataque de Mask-Generated (`-a 7`)**
    
    - **Descrição:** Aplica uma máscara ao início de cada palavra em uma wordlist.
    - **Uso:** `hashcat -m <hash_type> -a 7 <hash_file> <mask> <wordlist>`
    - **Exemplo:** `hashcat -m 0 -a 7 hashes.txt ?d?d rockyou.txt`
8. **Ataque de Hybrid Wordlist + Mask (`-a 8`)**
    
    - **Descrição:** Utiliza uma combinação de uma wordlist e uma máscara. Isso aplica a máscara tanto no início quanto no final da wordlist.
    - **Uso:** `hashcat -m <hash_type> -a 8 <hash_file> <wordlist> <mask>`
    - **Exemplo:** `hashcat -m 0 -a 8 hashes.txt rockyou.txt ?d?d?d`
9. **Ataque de Hybrid Mask + Wordlist (`-a 9`)**
    
    - **Descrição:** Utiliza uma combinação de uma máscara e uma wordlist. Aplica a máscara tanto no início quanto no final da wordlist.
    - **Uso:** `hashcat -m <hash_type> -a 9 <hash_file> <mask> <wordlist>`
    - **Exemplo:** `hashcat -m 0 -a 9 hashes.txt ?d?d?d rockyou.txt`

listar exemplos de hashes:
```
hashcat --example-hashes
```

hashcat para identificar a hash
```
hashcat --identify aba63f26d5947a558d4fdbbbe4468965710520540ef3d48e0b3cbf79d6cba217
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

## unshadow
```
unshadow passwd shadow >  hashes_formatadas
```
```
john hashes_formatadas
```

# wget
para baixar todo conteudo de uma página
```
wget -m <URL>
```

# grep
buscar uma string em todo o sistema
```
grep -ri "desec" /caminho/do/diretorio 2>/dev/null
```
# ritual
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo
fg
export TERM=xterm
```

# identificar hashes
hashid
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
sudo crackmapexec smb 10.10.11.35 -d cicada.htb -u @users.txt -p '' --shares
```


# Active Directory
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


Um **SID** típico segue o formato:

|**RID**|**Descrição**|
|---|---|
|**500**|Administrador|
|**501**|Convidado|
|**512**|Grupo Administradores do Domínio|
|**513**|Grupo Usuários do Domínio|
|**1000+**|Contas de usuários criadas manualmente|
bruteforce de RID
```
crackmapexec smb 10.10.11.35 -u guest -p '' -d cicada.htb --shares --rid-brute
```
