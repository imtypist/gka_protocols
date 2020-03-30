#include <stdio.h>
#include <stdlib.h>

#define NUMCERT 101
#define machine_base "node"
#define PATH "~/openssl-0.9.6/apps"

#define START 26
#define NUM_MACHINES 51

int main()
{
  FILE *fo;
  
  int i=0, j=0;
  char command[512], machine[100];

  fo = fopen("yy", "w");	
  fprintf(fo, "y\n");
  fprintf(fo, "y\n");
  fclose(fo);

  for(j=START; j<NUM_MACHINES; j++) {
    sprintf(machine, "%s%d", machine_base, j);
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
      
      sprintf(command, "%s/openssl genrsa -3 1024 > %03d%s_priv.pem", PATH, i, machine);
      printf("%s\n", command); 
      system(command);
      
      sprintf(command, "%s/openssl req -new -out %03d%s_req.pem -days 800 -nodes -key %03d%s_priv.pem <tmp", 
	      PATH, i, machine, i, machine);
      printf("%s\n", command);
      system(command);
      
      sprintf(command, "%s/openssl ca -out %03d%s_cert.pem -policy policy_anything -infiles %03d%s_req.pem < yy", 
	      PATH, i, machine, i, machine);
      printf("%s\n", command);
      system(command);
    }
  }

  return 0;
}
