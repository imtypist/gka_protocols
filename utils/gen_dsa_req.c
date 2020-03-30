#include <stdio.h>
#include <stdlib.h>

#define NUMCERT 4

int main()
{
  FILE *fo;
  
  int i=0;
  char command[512];
  
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


    sprintf(command, "openssl req -out %03d_req.pem -days 365 -nodes -newkey dsa:dsa_param.pem -keyout %03d_priv.pem <tmp",i,i);

    printf("%s\n", command);
    system(command);
    
    sprintf(command, "openssl ca -out %03d_cert.pem -policy policy_anything -infiles %03d_req.pem",i,i);
    
	printf("%s\n", command);
    system(command);

  }

  return 0;
}
