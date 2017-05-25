# xt_xff

iptables module to match ip block in http X-Forwarded-For

build
======

need package `iptables-devel`,`kernel-headers` and `kernel-devel`

    $ make
    $ sudo make install
    $ sudo insmod xt_xff.ko

Examples
==========

    [root@bs203 ipt_xff]# insmod xt_xff.ko
    [root@bs203 ipt_xff]# iptables -I INPUT -p tcp --dport 80 -m xff --algo kmp --cidr 1.2.3.255/25 --to 256 -j DROP
    [root@bs203 ipt_xff]# curl -I localhost -H 'X-Forwarded-For: 1.2.3.127'
    HTTP/1.1 200 OK
    Server: nginx/1.10.2
    Date: Thu, 25 May 2017 12:15:37 GMT
    Content-Type: text/html
    Content-Length: 927
    Last-Modified: Wed, 17 May 2017 11:00:33 GMT
    Connection: keep-alive
    ETag: "591c2d51-39f"
    Accept-Ranges: bytes
    
    [root@bs203 ipt_xff]# curl -I localhost -H 'X-Forwarded-For: 1.2.3.128'
    curl: (52) Empty reply from server

becasue the connection is already in ESTABLISHED state when i got http headers, so the connect can't be properly closed. maybe a better choice is to use it with an other project of mine: [ipt_TRASH](https://github.com/Dyluck/ipt_TRASH) ? ^-^

