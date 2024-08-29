  

![](https://lh7-us.googleusercontent.com/docsz/AD_4nXfPY2u7a3fgtRM0q4CqVuby4qKYOQFeqcf26X8ooxQ5FhTSfGzYssdE46EM8eEfVWaOEltwGbp0ROj4_eCzvNHOXWGbVdr-wBUkklwRsHAKp9ntoS4I9ruiuROHa8N26Z0hRX4eagI3Gx10jey0ZOoRCIG4?key=DzYtBEZqL9HFVg1Oepk-ag)

Grupo de Resposta a Incidentes de Segurança - Universidade Federal do Rio de Janeiro

  
  
  
  
  
  

Jhayson Jales

  
  
  
  
  
  
  
  
  
  
  

Segurança Ofensiva

  
  
  
  
  
  
  

Rio de janeiro

2024 - ∞  

  

  

# Projeto de Segurança Ofensiva

  

  

O que pretendemos abordar nesta apresentação?

  
  
  

O que foi necessário para reproduzirmos esses cenários?

  
  

Introdução às ferramentas utilizadas

  

Idealizado por [Jhayson Jales] 

  
  
  
  
  

# Enumeração

## tipos de usuários

Non-root Usuários non-root são todos os usuários que não têm privilégios administrativos completos. O usuário “root” é o superusuário em sistemas Unix/Linux com controle total sobre o sistema. Usuários non-root têm permissões restritas, dependendo das políticas de segurança do sistema.

Non-service Usuários non-service referem-se a contas de usuário que não são usadas para rodar serviços do sistema. Em sistemas Unix/Linux, muitos serviços de sistema, como web servers, bancos de dados, e outros daemon, rodam sob contas de usuário específicas para isolar e limitar o impacto de possíveis comprometimentos de segurança. Contas de serviço tipicamente têm UIDs baixos (geralmente menores que 1000).

Non-daemon Daemons são programas que rodam em segundo plano para realizar tarefas específicas, como servidores de email, web servers, e outros. Contas non-daemon são contas de usuário que não são usadas para rodar esses programas de segundo plano.

Podemos enumerar essas informações com o comando abaixo:
```
grep -E "non-root|non-service|non-daemon" /etc/passwd
```
  

## Usos Comuns do /usr/sbin/nologin

Contas de Serviço e Sistema: Muitas vezes, contas de usuário associadas a serviços e processos de sistema (como ftp, www-data, nobody, etc.) são configuradas com /usr/sbin/nologin para evitar que alguém possa usar essas contas para acessar o sistema diretamente.

## Versão do Linux

Para enumerar a versão do linux podemos usar os seguintes comandos:
```
lsb_release -a
lsb_release -d
cat /etc/os-release
hostnamectl
cat /proc/version
```
  

## Buscando por arquivos e diretórios

Para procurar por arquivos e diretórios de nome motd, podemos usar os seguintes comandos:
```
locate motd
find / -name motd
```
  

# Command Injection/Shell injection

O tipo de vulnerabilidade Command Injection ocorre quando temos uma linguagem do tipo server-side em que a aplicação web faz uma chamada de sistema no computador de hospedagem.

[https://www.youtube.com/watch?v=8PDDjCW5XWw](https://www.youtube.com/watch?v=8PDDjCW5XWw)

[Hacktricks Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)

Exemplo de Linguagens server-side:
- php
- python
- java
- ruby
- node.js
- go
- c#
- perl
- rust

**Comandos Linux**
```
whoami
id   
ifconfig
ip addr
uname -a
ps -ef
```
  

**Comandos Windows**
```
whoami   
ver
ipconfig   
tasklist
netstat -an
```    

## Blind Command Injection/Shell injection

Em alguns casos, a aplicação web não reflete o output do comando para a aplicação web, neste caso vamos utilizar técnicas de blind command injection.

Comandos Linux:

```
& ping -c 15 127.0.0.1
sleep 10
```

Comandos Windows:

```
ping -n 10 127.0.0.1
timeout /T 10
```

Obs: Neste caso precisaríamos ter certeza que o host possui `ping`, `sleep` e `timeout` 

## Laboratórios de command injection

[TryHackMe](https://tryhackme.com/r/room/owasptop10)

[Portswigger](https://portswigger.net/web-security/all-labs#os-command-injection)



# falta fazer
precisa do burp collaborator?
- https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band
- https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration

configurar bwapp -  https://www.youtube.com/watch?v=AoLrB_p6rF4
download bwapp - https://sourceforge.net/projects/bwapp/files/bee-box/
# Referências

laboratório TryHackMe - [https://tryhackme.com/r/room/owasptop10](https://tryhackme.com/r/room/owasptop10)

[Portswigger Command Injection](https://portswigger.net/web-security/os-command-injection#what-is-os-command-injection)