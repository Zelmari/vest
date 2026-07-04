/*
 * Vulnerable demo program for VEST binary scanner testing.
 *
 * Compile (macOS Mach-O / Linux ELF):
 *   gcc -fno-stack-protector -Wl,-no_pie -o vuln vuln.c
 *   (On ARM64 macOS, -Wl,-no_pie may be ignored; PIE is mandatory)
 *
 * Flags:
 *   -fno-stack-protector   — disable stack canaries
 *   -Wl,-no_pie / -no-pie  — disable position-independent executable (ASLR bypass)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 16

void read_input(char *dest) {
    char buf[BUFSIZE];
    printf("Enter some text: ");
    gets(buf);                    /* buffer overflow */
    strcpy(dest, buf);            /* unbounded copy */
}

void print_message(const char *msg) {
    printf(msg);                  /* format string vulnerability */
}

void exec_command(const char *cmd) {
    char buf[BUFSIZE * 4];
    sprintf(buf, "echo Running: %s", cmd);
    printf("%s\n", buf);
    system(cmd);                  /* command injection */
}

int main(int argc, char **argv) {
    char storage[BUFSIZE * 2];

    if (argc > 1) {
        print_message(argv[1]);
        exec_command(argv[1]);
    } else {
        read_input(storage);
        printf("You entered: %s\n", storage);
    }

    return 0;
}
