mysh: shell.c
	gcc shell.c -g -lssl -lcrypto -o mysh

clean:
	rm -f mysh