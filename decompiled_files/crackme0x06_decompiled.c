#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_PASSWORD_LENGTH 120

/* --- Function: dummy --- */


int dummy(char *password,int offset)

{
  int iVar1;
  int password_index;
  int iteration;
  
  iteration = 0;
  do {
    if (*(int *)(iteration * 4 + offset) == 0) {
      return 0;
    }
    iVar1 = iteration * 4;
    iteration = iteration + 1;
    password_index = strncmp(*(char **)(iVar1 + offset),"LOLO",3);
  } while (password_index != 0);
  return 1;
}


/* --- Function: parell --- */


void parell(char *password,int secret)

{
  int result;
  int iteration;
  uint password_value;
  
  sscanf(password,"%d",&password_value);
  result = dummy((char *)password_value,secret);
  if (result != 0) {
    for (iteration = 0; iteration < 10; iteration = iteration + 1) {
      if ((password_value & 1) == 0) {
        printf("Password OK!\n");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
    }
  }
  return;
}


/* --- Function: check --- */


void check(char *password,int secret)

{
  size_t password_length;
  char current_char;
  uint index;
  int checksum;
  int digit;
  
  checksum = 0;
  index = 0;
  while( 1 ) {
    password_length = strlen(password);
    if (password_length <= index) break;
    current_char = password[index];
    sscanf(&current_char,"%d",&digit);
    checksum = checksum + digit;
    if (checksum == 16) {
      parell(password,secret);
    }
    index = index + 1;
  }
  printf("Password Incorrect!\n");
  return;
}


/* --- Function: main --- */


int main(int argc,char **argv,char **envp)

{
  char password [120];
  
  printf("IOLI Crackme Level 0x06\n");
  printf("Password: ");
  scanf("%s",password);
  check(password,(int)envp);
  return 0;
}

