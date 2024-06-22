#include <stdio.h>
#include <string.h>


void setup(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}


int main(){
    setup();

    char username[0x100];
    printf("What's your name?\n> ");

    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Hello, %s!\n", username);

    return 0;
}


