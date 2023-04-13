功能：
加密和解密

rsa_file
从文件读取公钥和私钥

rsa_str
从代码内的字符串读取公钥和私钥

编译：
gcc -o rsa_str rsa_str.c -lssl -lcrypto

private_key.pem和public_key.pem需要放到相同文件夹内
