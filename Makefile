LDFLAGS=-L/usr/local/opt/openssl/lib
CPPFLAGS= -I/usr/local/opt/openssl/include
CC=gcc


certcheck: certcheck.c
	$(CC) -o certcheck certcheck.c -lssl -lcrypto

clean:
	rm certcheck
