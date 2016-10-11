
#include <stdio.h>

int checkPassword() {
  char pass[16];
  bzero(pass, 16); // initialize
  printf ("Enter password: ");
  gets(pass);
  if (strcmp(pass, "opensesame") == 0)
    return 1;
  else 
    return 0;
}

void openVault() {
  // opens the vault
}
 
 main() {
   if (checkPassword()) {
     openVault();
     printf ("Vault opened!");
  }
}
