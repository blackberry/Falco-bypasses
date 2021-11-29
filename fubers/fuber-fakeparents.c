#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  /* 
  eg: fuber "cat /etc/shadow" "automount" 3
  argv[0]: executable name              - fuber
  argv[1]: command to run               - cat /etc/shadow
  argv[2]: name of current process      - automount
  argv[3]: successor depth              - 3
  */
  if (argc != 4)
  {
    perror("3 arguments needed: command to run, name of the current process and the successor depth.");
    return -1;
  }

  // convert depth to a char
  short depth;
  sscanf(argv[3], "%hd", &depth);

  // rename current proc to argv[2]
  if (prctl(PR_SET_NAME, (unsigned long)argv[2]) == -1)
  {
    perror("prctl failed");
    return -1;
  }

  // splitting argv[1]
  char **res = NULL;
  char *p = strtok(argv[1], " ");
  int n_spaces = 0, i;

  while (p)
  {
    res = realloc(res, sizeof(char *) * ++n_spaces);

    if (res == NULL)
      exit(-1); /* memory allocation failed */

    res[n_spaces - 1] = p;

    p = strtok(NULL, " ");
  }
  res = realloc(res, sizeof(char *) * (n_spaces + 1));
  res[n_spaces] = 0;

  // if(depth == 0) {
  //   char *newpname = res[0];
  //   res[0] = argv[2];
  //   execvp(newpname, res);
  //   perror("execvp");
  //   return 0;
  // }

  while (depth >= 0)
  {
    pid_t pid = fork();
    if (depth == 0 && pid == 0)
    {
      // execvp
      execvp(res[0], res);
      perror("execvp");
    }
    else if (pid != 0)
    {
      int status;
      pid_t terminated;

      terminated = waitpid(pid, &status, 0);
      if (terminated == -1)
      {
        perror("waitpid");
        exit(1);
      }
      break;
    }

    --depth;
  }

  return 0;
}

