#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static void exit(int status);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  int syscall_code = *(int*)f->esp;
  if (syscall_code == SYS_HALT){
    shutdown_power_off();
  }
  else if(syscall_code ==  SYS_WAIT){
    tid_t pid = (tid_t)(*((int*)f->esp +1));
    f->eax = process_wait(pid);

  }
  else if(syscall_code == SYS_EXIT){
     int status = *((int*)f->esp + 1);
	  exit(status);
  }else if(syscall_code == SYS_EXEC){

    char *cmd_line = (char*)(*((int*)f->esp +1));

    if(!is_valid(cmd_line))
      exit(-1);

    f->eax = process_execute(cmd_line);

  }



  printf ("system call!\n");
  thread_exit ();
}

static void exit(int status){
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_current()->mis_datos->return_state = status;
  thread_exit();
}

static bool is_valid(void *addr){

  bool ret = true;
  for(int i=0, i<4; i++){
    if(!is_user_vaddr(addr)){
      ret = false;
      break;
    }else{
      if(pagedir_get_page(thread_current()-> pagedir, addr)== NULL){
        ret = false;
        break;
      }
      addr++;
    }
    return ret;
  }

}
