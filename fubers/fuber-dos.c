#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  FILE* fp;
  int i = 0;
  char buf[1024];

  if (argc != 3){
    printf("You need to provide a number of dummy syscalls and a command to run!\n");
    return 0;
  }

  int iters = atoi(argv[1]);

  //mask the real call
  for (i=0; i<iters; i++)
  {
    fp = fopen("/etc/passwd","r");
    fclose(fp);
  }
  
  //-----------------Real call--------------------//
  FILE *fpp;

  if ((fpp = popen(argv[2], "r")) == NULL) {
    printf("Error opening pipe!\n");
    return -1;
  }
  
  while (fgets(buf, 1024, fpp) != NULL)
    printf("OUTPUT: %s", buf);

  if(pclose(fpp))  {
    printf("Command not found or exited with error status\n");
    return -1;
  }

  //mask the real call
  for (i=0; i<iters; i++)
  {
    fp = fopen("/etc/passwd","r");
    fclose(fp);
  }
}
