#include <stdio.h>
#include <stdlib.h>

#define NUMCERT 51
int main()
{
  FILE *fo;
  
  int i=0;
  char command[512];

  fo = fopen("yy", "w");	
  fprintf(fo, "y\n");
  fprintf(fo, "y\n");
  fclose(fo);

  for(i=0; i<NUMCERT; i++){
  fo = fopen("tmp", "w");

    fprintf(fo, "CN\n");
    fprintf(fo, "Shanghai\n");
    fprintf(fo, "Shanghai\n");
    fprintf(fo, "SJTU\n");
    fprintf(fo, "SCE\n");
    fprintf(fo, "%03d\n",i);
    fprintf(fo, "%03d@sjtu.edu.cn\n",i);
    fprintf(fo, ".\n");
    fprintf(fo, ".\n");

    fclose(fo);


    sprintf(command, "openssl req -out %03dfog2_req.pem -days 365 -nodes -newkey rsa:2048 -keyout %03dfog2_priv.pem <tmp",i,i);

    printf("%s\n", command);
    system(command);
    
    sprintf(command, "openssl ca -out %03dfog2_cert.pem -policy policy_anything -infiles %03dfog2_req.pem < yy",i,i);
    
    printf("%s\n", command);
    system(command);

  }

  return 0;
}
