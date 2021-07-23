#include <stdio.h>

int main(int argc, char *argv[]) {
   FILE *fp;
   char str[1024];

   if( argc != 2 ) {
      printf("Provide the file name to read.\n");
      return 0;
   }
   fp = fopen(argv[1], "rb");
   if (fp) {
      while (fscanf(fp, "%s", str)!=EOF)
         printf("%s",str);
      fclose(fp);
   }
   else 
      printf("No such file or file cannot be read.\n");
}
