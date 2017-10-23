#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/evp.h>

void error() {
    char error_message[30] = "An error has occurred\n";
    write(STDERR_FILENO, error_message, strlen(error_message));
}

void cleanup(char *args[]) {
    for (int i = 0; args[i] != NULL; i++) {
        free(args[i]);
    }
}

void hash(char input[]) {
    EVP_MD_CTX mdctx;
    const EVP_MD *md;
    unsigned char output[EVP_MAX_MD_SIZE];
    int output_len, i;
  
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname("MD5");
  
    if (!md) {
        printf("Unable to init MD5 digest\n");
        exit(1);
    }
  
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, md, NULL);
    EVP_DigestUpdate(&mdctx, input, strlen(input));

    EVP_DigestFinal_ex(&mdctx, output, &output_len);
    EVP_MD_CTX_cleanup(&mdctx);
    
    for (i = 0; i < output_len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
}

void parse(char input[], char *args[], int *count, int *redirect) {
    char *delim = " \t\n";
    char *token = strtok(input, delim);
    int rcount = 0;
    int rdiff = 0;
    int rinc = 0;
    while (token != NULL) {
        int len = strlen(token) + 1;
        rdiff += rinc;
        if (!strcmp(token, ">")) {
            *redirect = 1;
            rcount++;
            rinc = 1;
        }
        args[*count] = malloc(len * sizeof(char));
        strcpy(args[*count], token);
        args[len] = '\0';
        token = strtok(NULL, delim);
        (*count)++;
    }
    args[*count] = NULL;
    if (rcount > 1 || rdiff > 1) {
        error();
        *count = 0;
    }
}

void scriptify(char *args[], int len) {
    args[2] = NULL;
    args[1] = malloc(len * sizeof(char));
    strcpy(args[1], args[0]);
    char *command;
    if (args[0][len-1] == 'y') {
        command = malloc(strlen("python\0") * sizeof(char));
        strcpy(command, "python\0");
    } else if (args[0][len-1] == 'l') {
        command = malloc(strlen("perl\0") * sizeof(char));
        strcpy(command, "perl\0");
    }
    free(args[0]);
    args[0] = malloc(strlen(command) * sizeof(char));
    strcpy(args[0], command);
}

void execute(char *args[], int count) {
    if (!strcmp(args[0], "cd")) {
        char dir[512];
        count == 1 ? strcpy(dir, getenv("HOME")) : strcpy(dir, args[1]);
        chdir(dir);
    } else if (!strcmp(args[0], "hash")) {
        hash(args[1]);
    } else if (!strcmp(args[0], "pwd")) {
        char pwd[512];
        getcwd(pwd, sizeof(pwd));
        printf("%s\n", pwd);
    } else if (!strcmp(args[0], "exit")) {
        exit(0);
    } else if (!strcmp(args[0], "wait")) {
        int p;
        while ((p = wait(0)) != -1);
    } else {
        int bg = 0;
        if (!strcmp(args[count-1], "&")) {
            bg = 1;
        }
        pid_t p = fork();
        if (p == 0) {
            int len = strlen(args[0]);
            if (bg) {
                setpgid(0, 0);
                free(args[count-1]);
                args[count-1] = NULL;
            }
            if (args[0][len-2] == 'p' && args[0][len-3] == '.') {
                scriptify(args, len);
            }
            int result = execvp(args[0], args);
            error();
            _exit(0);
        } else {
            int stat;
            int w = waitpid(p, &stat, (bg ? WNOHANG : 0));
        }
    }
}

void interpret(char input[]) {
    char *args[100];
    int *count = malloc(sizeof(int));
    *count = 0;
    int *redirect = malloc(sizeof(int));
    *redirect = 0;
    parse(input, args, count, redirect);
    if (*count == 0) {
        goto CLEAN;
    }
    if(*redirect) {
        freopen(args[*count-1], "w", stdout);
        free(args[*count-1]);
        free(args[*count-2]);
        *count -= 2;
        args[*count] = NULL;
    }
    execute(args, *count);
    if (*redirect) {
        freopen("/dev/tty", "w", stdout);
    }
    CLEAN:
        cleanup(args);
        free(count);
        free(redirect);   
        signal(SIGCHLD, SIG_IGN);        
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        while (1) {
            printf("mysh> ");
            char input[512];
            fgets(input, 512, stdin);
            interpret(input);
        }
    } else if (argc == 2) {
        int len = strlen(argv[1]);
        FILE *batch = fopen(argv[1], "r");
        if (batch == NULL) {
            error();
        } else {
            char *line = NULL;
            size_t len = 0;
            ssize_t r;
            while ((r = getline(&line, &len, batch)) != -1) {
                interpret(line);
            }
            free(line);
            fclose(batch);
        }
    } else {
        error();
    }
    return 0;
}