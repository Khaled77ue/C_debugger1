#include "elf64.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>





pid_t run_target(const char* programname);
void run_print_while_running(pid_t child_pid,long int address_to_start);
long int hexadecimalToDecimal(char hexVal[]) ;


bool stringCmp(const char* string1,const char* string2){
   // printf("%s\n",str1);
  //  printf("%s\n",str2);
  int arched=0;
    while(*string1 && *string2){
        if(*string1 != *string2)
            return false;
        
        string2++;
        string1++;
    }
    if(*string1 || *string2){
        return false;}
        
        
        arched=1;
    return true;
}

int get_adrr(const char* prog_name, const char* func_name,Elf64_Addr* func_address){
    FILE* excutable;
     excutable=fopen(prog_name, "rb"); 
int text_index;
    
    Elf64_Ehdr* header = malloc(sizeof(Elf64_Ehdr));
    fread(header, sizeof(Elf64_Ehdr), 1, excutable);

  
    Elf64_Shdr* Section_header = malloc(sizeof(Elf64_Shdr));
    
    
    Elf64_Addr offset_to_shstrtab = header->e_shoff + header->e_shentsize*header->e_shstrndx;
    
    fseek(excutable, offset_to_shstrtab, SEEK_SET);
    
    fread(Section_header, sizeof(Elf64_Shdr), 1, excutable);
    
    char* strings = malloc(Section_header->sh_size*sizeof(char));
    
    fseek(excutable,Section_header->sh_offset, SEEK_SET);
    
    fread(strings, Section_header->sh_size, 1, excutable);


    
    Elf64_Shdr* section_header = malloc(sizeof(Elf64_Shdr));
  
    bool symtable_found = false;
    bool strtable_found = false;


    Elf64_Shdr* strtable_header = malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr* symtable_header = malloc(sizeof(Elf64_Shdr));
    for(int i=0; i<header->e_shnum; i++){
        Elf64_Addr offset_to_section = header->e_shoff + i*header->e_shentsize;
        fseek(excutable, offset_to_section, SEEK_SET);
        fread(section_header, sizeof(Elf64_Shdr), 1, excutable);
   

      
          if(stringCmp((strings+section_header->sh_name), ".text")){
			  text_index=i;
			
			  
			  }
  if(stringCmp((strings+section_header->sh_name), ".symtab")){

            memcpy(symtable_header, section_header, sizeof(Elf64_Shdr));
            symtable_found = true;
        }
        if(stringCmp((strings+section_header->sh_name), ".strtab")){

            strtable_found = true;
            memcpy(strtable_header, section_header, sizeof(Elf64_Shdr));
        }
      }
    
    char* symbol_strings = malloc(sizeof(char)*strtable_header->sh_size);
    fseek(excutable, strtable_header->sh_offset, SEEK_SET);
    fread(symbol_strings, strtable_header->sh_size, 1, excutable);



    
    bool func_found = false;
    Elf64_Sym* symbol_entry = malloc(sizeof(Elf64_Sym));
    for(int i=0; i<(symtable_header->sh_size / symtable_header->sh_entsize); i++){
        Elf64_Addr offset_to_entry = symtable_header->sh_offset + i*symtable_header->sh_entsize;
        fseek(excutable, offset_to_entry, SEEK_SET);
        fread(symbol_entry, sizeof(Elf64_Sym), 1, excutable);

     
        if(stringCmp((symbol_strings+symbol_entry->st_name), func_name)&&symbol_entry->st_shndx==text_index) {
			     
    func_found = true;
            break;
        }
    }
    

   
    if(!func_found){
        printf("PRF:: not found!\n");
        return 0;
    }
   
    if(ELF64_ST_BIND(symbol_entry->st_info) == 0){ 
        printf("PRF:: local found!\n");
        return 0;
    }

    *func_address = symbol_entry->st_value;

    free(section_header);

    free(Section_header);

    free(strings);

    free(symtable_header);

    free(strtable_header);

    free(symbol_entry);

    free(header);

    free(symbol_strings);

    fclose(excutable);



    return 1;
}

int main(int argc, char *argv[]) {
   Elf64_Addr rip_wanted_address;
   // char how_to_print=argv[2][0];
char* func_wanted=argv[1];
if(get_adrr(argv[2],func_wanted,&rip_wanted_address)==0){
	return 1;
	}
	//printf("\nhi we finished shit\n");
    pid_t child_pid;
    child_pid=run_target(argv[2]);

    run_print_while_running(child_pid,rip_wanted_address);

return 0;
}




long int hexadecimalToDecimal(char hexVal[])
{
    int len = strlen(hexVal);

    // Initializing base value to 1, i.e 16^0
    int base = 1;

   long int dec_val = 0;

    // Extracting characters as digits from last character
    for (int i=len-1; i>=0; i--)
    {
        // if character lies in '0'-'9', converting
        // it to integral 0-9 by subtracting 48 from
        // ASCII value.
        if (hexVal[i]>='0' && hexVal[i]<='9')
        {
            dec_val += (hexVal[i] - 48)*base;

            // incrementing base by power
            base = base * 16;
        }

            // if character lies in 'A'-'F' , converting
            // it to integral 10 - 15 by subtracting 55
            // from ASCII value
        else if (hexVal[i]>='a' && hexVal[i]<='f')
        {
            dec_val += (hexVal[i] - 87)*base;

            // incrementing base by power
            base = base*16;
        }
    }

    return dec_val;
}

void run_print_while_running(pid_t child_pid,long int address_to_start){
int wait_status;
wait(&wait_status);
//printf("\n is %d \n",address_to_start);
    
//waitpid(child_pid,&wait_status,WUNTRACED);
    struct user_regs_struct regs;
char buffer[16]={0};
char instrly=0;
int after_Sys=0;
int counter=0;
//waitpid(child_pid,&wait_status,WUNTRACED);
 
//printf("\n address to start is %d \n",address_to_start);
bool arrived=false;

    while (WIFSTOPPED(wait_status)) {
 
 //printf("\n instruction is %d \n",0);
//ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
//if(regs.rax<0){
	//printf("come to daddy %d",regs.rax);
//	}
unsigned long last_rip=regs.rip;
    if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
      wait(&wait_status);

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        //printf("\n instruction is %d \n",0);
        long int instruc=ptrace(PTRACE_PEEKDATA,child_pid,regs.rip,0);
unsigned short int instr=instruc ;
     // printf("\n instruction is %d \n",instr);
        
instrly=(char)instr;
 int dd=instrly;
  //printf("\n instruction is %d \n",dd);
        if(regs.rip==address_to_start){
//printf("\nal zanati wasal\n");
            arrived=true;
//continue;

        }
        if(arrived){
//printf("\nal zanati wasal\n");
			if(after_Sys==1){
				after_Sys=0;
				
				int rax=regs.rax;
				 if(rax<0){
					 
					 sprintf(buffer, "%06lx", last_rip & 0xFFFFFFUL);
printf("PRF:: syscall in %s returned with %lld\n",buffer,regs.rax);
    }
				}

if(dd==-24){
counter++;
}

//printf("\n counter is %d\n",counter);

if(dd==-61&&counter==0){
//printf("\nal zanati rawa7\n");
	//printf("\n we are out \n");
 arrived=false;
//continue;

}
if(dd==-61&&counter>0){
counter--;
}

if(instr==1295){
///printf("\nal zanati wasal al sys\n");
	//printf("\n %d \n",address_to_start);
after_Sys=1;
}
   
}
}
}

pid_t run_target(const char* programname)
{
    pid_t pid;

    pid = fork();

    if (pid > 0) {

        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */

        execl(programname, programname, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
 return pid;
}


