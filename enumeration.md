# enumeração



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

## Firewall
```
wafw00f example.com
```


## ftp (21)
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

### ftp (passivo x ativo)
referencial é o servidor
- No modo FTP passivo o servidor fica escutando enquanto aguarda a conexão do cliente. 
- No modo FTP ativo, o cliente fica escutando enquanto aguarda a conexão do servidor.

Modo Passivo:
    No modo passivo, o cliente estabelece tanto a conexão de controle (porta 21) quanto a conexão de dados. Após estabelecer a conexão de controle, o cliente solicita ao servidor uma porta para a conexão de dados. O servidor então informa ao cliente qual porta ele (o servidor) está escutando para a conexão de dados (geralmente uma porta acima de 1023). O cliente, então, abre uma conexão para essa porta no servidor.

Modo Ativo:
    No modo ativo, o cliente estabelece a conexão de controle com o servidor na porta 21. Quando é necessário transferir dados, o cliente informa ao servidor qual porta ele (o cliente) está escutando para a conexão de dados (normalmente uma porta acima de 1023). O servidor então abre uma conexão a partir de sua porta 20 para a porta especificada pelo cliente.



## NetBios/SMB
Permite o compartilhamento de arquivos/diretórios na rede.


NetBios (porta 139) --> antigo
SMB (porta 445) --> mais recente

Identifica hosts e informações de NetBIOS em uma rede (classe C)
```
sudo nbtscan 192.168.0.0/24

192.168.0.1    <00> UNIQUE   "MYPC"       [MYGROUP]
192.168.0.2    <00> UNIQUE   "ANOTHERTPC" [MYGROUP]
192.168.0.3    <00> UNIQUE   "SERVER"     [MYGROUP]

```

Em alguns casos o netbios/smb permite o login apenas com o usuário e senha vazia.
```
smbclient //hostname/sharename -U username%
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

### via windows
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

## rpc (Remote Procedure Call)
O RPC é uma API que permite a um programa executar um procedimento (ou função) em outro espaço de endereço, como em um servidor remoto, como se fosse uma chamada local
conectando ao servidor com usuário e senha
```
rpcclient -U <username>%<password> <hostname_or_ip>
```
conectando ao servidor via Null Session
```
rpcclient -U "" -N <hostname_or_ip>
```

### comandos úteis:
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
## pop3 (110)
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

## SMTP
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

## Enumerando Dispositivos de Rede
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

## ssh (secure shell)
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

### Autenticação com chave pública
basta adicionar a nossa chave pública no arquivo `authorized_keys`

gerando par de chave público/privada
```
ssh-keygen
id_rsa  id_rsa.pub
```
- `id_rsa` é a chave privada
- `id_rsa.pub` é a chave pública

### Arquivo de configuração
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


## SNMP
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

### snmpwalk
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

### snmptranslate
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


## mysql
porta default: 3306

testar credenciais default

conexão com o servidor (senha nula) e usuário mysql/root
```
mysql -h 192.168.0.5 -u mysql
mysql -h 192.168.0.5 -u root
```



## tools
### Hydra
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


### gobuster
```
gobuster -u http://10.10.206.2 -w ~/wordlist/SecLists/Discovery/Web-Content/raft-large-directories.txt -t 100 -e 
```
-e printa a url toda
-t numero de threads
-u url
-x string              File extension(s) to search for (dir mode only)
-p string              Proxy to use for requests [http(s)://host:port] (dir mode only)

