
## Permissões de Arquivos
```
└─$ ls -la
total 840
drwxr-xr-x  3 romio romio   4096 Aug 29 17:59  .
drwxr-x--- 33 romio romio   4096 Aug 29 17:56  ..
-rw-rw-r--  1 romio romio      0 Aug 29 17:59  file.txt

```

**primeira coluna:** 
- **`d`**: Diretório (por exemplo, `drwxr-xr-x` para um diretório).
- **`-`**: Arquivo regular (por exemplo, `-rw-rw-r--` para um arquivo).
- **`l`**: Link simbólico (por exemplo, `lrwxrwxrwx` para um link simbólico).

Existem outros tipos de arquivos - https://www.geeksforgeeks.org/how-to-find-out-file-types-in-linux/


**Segunda, Terceira e Quarta Coluna:** Permissões para o Proprietário

- **`r`**: Permissão de leitura (Read).
- **`w`**: Permissão de escrita (Write).
- **`x`**: Permissão de execução (Execute).

Por exemplo, para o arquivo `file.txt`:

- **`rw-`**: O proprietário tem permissões de leitura e escrita, mas não de execução.

**Quinta, Sexta e Sétima Coluna:** Permissões para o Grupo

- **`r`**: Permissão de leitura (Read).
- **`w`**: Permissão de escrita (Write).
- **`x`**: Permissão de execução (Execute).

Para `file.txt`:

- **`rw-`**: O grupo tem permissões de leitura e escrita, mas não de execução.

**Oitava, Nona e Décima Coluna:** Permissões para Outros Usuários

- **`r`**: Permissão de leitura (Read).
- **`w`**: Permissão de escrita (Write).
- **`x`**: Permissão de execução (Execute).

Para `file.txt`:

- **`r--`**: Outros usuários têm permissão de leitura, mas não de escrita ou execução.

SUID
arquivos executados por quem os criou

```
find / -user root -perm /4000
```


procurar por nome de arquivo:
```
find / -name "user.txt" 2>/dev/null
```


## linux smart enumeration (LSE)
https://github.com/diego-treitos/linux-smart-enumeration




