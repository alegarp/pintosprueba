#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "devices/input.h"
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *);
static void exit(int status);
static bool is_valid(void *addr);
static struct file * search_file(int fd);
struct lock lock_filesys;



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&lock_filesys);
}

/*
Entre 1 a 3 argumentos pag 44
Frame stack pointer f->esp
info de sys?code esta en src/lib/syscallnr.h.
*/

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  if(!is_valid(f->esp))
    exit(-1);

  	int syscall_code = *(int*)f->esp;
	char* cmd_line;
	int status;
	int fd;
	struct file *file;
	char *file_n;
	tid_t pid;
	void *buffer;
	unsigned size;
	unsigned position;



    switch (syscall_code)
   	{
    	case SYS_HALT:
      //  printf("HALT");
    	//esta declarado en init y es para terminar pintos
        	shutdown_power_off();
    	break;


    	case SYS_EXIT:
      //  printf("EXIT");
    	//da el status kernel, si es 0 exito sino error
    		if(!is_valid((int*)f->esp + 1))
      			exit(-1);

      		status = *((int*)f->esp + 1);
          	exit(status);
    	break;



      case SYS_EXEC:
      //  printf("EXEC");
      // pid del process
	  // Si pid es -1 no ha terminado o salio algo malo

	    if(!is_valid((int*)f->esp + 1))
	      exit(-1);

		cmd_line = (char*)(*((int*)f->esp + 1));

		//sino es de valido el ejecutable		
	    if(!is_valid(cmd_line))
	        exit(-1);
	    //process con el ejecutable para que devuelva la info 
	    f->eax = process_execute(cmd_line);

      break;



    	case SYS_WAIT:
      //  printf("WAIT");
    	//espera una vez al hijo 
	    	if(!is_valid((int*)f->esp + 1))
	      		exit(-1);
	      //buscando el del hijo y conociendo el estado
	      pid = (tid_t)(*((int*)f->esp + 1));
	      f->eax = process_wait(pid); //vamos a process

    	break;


    	case SYS_CREATE: 
      //  printf("CREATE");
    	//crea nuevo archivo con size bytes de tam 
    							//arg size inicial, file
    		if(!is_valid((int*)f->esp + 1))
      			exit(-1);

      		if(!is_valid((int*)f->esp + 2))
      			exit(-1);

      		//nom archivo
    	    file_n = (char*)(*((int*)f->esp + 1));
    	    //size ini
		    unsigned initial_size = (unsigned)(*((int*)f->esp + 2));


		    if(!is_valid(file_n))
		        exit(-1);

      		//filesys
	      	filesys_lock_acquire();
	      	f->eax = filesys_create(file_n, initial_size);
	      	filesys_lock_release();
        break;



        case SYS_REMOVE:
      //  printf("REMOVE");
        //nombre archivo
          if(!is_valid((int*)f->esp + 1))
            exit(-1);
			//
            file_n = (char*)(*((int*)f->esp + 1));
		    if(!is_valid(file_n))
		      exit(-1);

		  	//filesys
		    filesys_lock_acquire();
		    f->eax = filesys_remove(file_n);
		    filesys_lock_release();
      	break;




        case SYS_OPEN:
      //  printf("OPEN");  
        //file   
	    if(!is_valid((int*)f->esp + 1))
	      exit(-1);

	      file_n = (char*)(*((int*)f->esp + 1));
	      struct file *open_file;

	      if(!is_valid(file_n ))
	        exit(-1);
	      //abrir archivo filesys
	      filesys_lock_acquire();
	      open_file = filesys_open(file_n );
	      filesys_lock_release();
	      //
	      if(open_file == NULL)
	      {
	        f->eax = -1;
	      }
	      else
	      {
	        if(strcmp(file_n , thread_current()->name) == 0)
	          file_deny_write(open_file);
	        list_push_back(&thread_current()->open_files, &open_file->file_elem);
	        f->eax = open_file->fd;
	      }
      	break;





      	case SYS_FILESIZE:
      //  printf("FILESIZE");
	        fd = *((int*)f->esp + 1);
	        file = search_file(fd);
	        if(file == NULL)
	          f->eax = -1;
	        else
	          f->eax = file_length(file);
      	break;




    	case SYS_READ:

      	    if(!is_valid((int*)f->esp + 3))
        		exit(-1);

	        int i;
	        fd = *((int*)f->esp + 1);

	        buffer = (void*)(*((int*)f->esp + 2));
	        size = *((unsigned*)f->esp + 3);

	        if(!is_valid(buffer))
	            exit(-1);

	        if(fd == 0)
	        {
	            for(i = 0; i < size; i++)
	            {
	            	((char*)buffer)[i] = input_getc();
	            }
	            f->eax = i;
	        }
	        else
	        {
	    	    file = search_file(fd);
	            if(file == NULL)
	                f->eax = -1;
	            else
	                f->eax = file_read(file, buffer, size);
	        }
        break;




    	case SYS_WRITE:
      //  printf("WRITE"); pag 45

		if(!is_valid((int*)f->esp + 3))
        	exit(-1);

	      if(syscall_code == SYS_WRITE)
	      {

	        fd = *((int*)f->esp + 1);
	        buffer = (void*)(*((int*)f->esp + 2));
	        size = *((unsigned*)f->esp + 3);

	        if(!is_valid(buffer))
	            exit(-1);

	        if(fd == 1)
	        {
	        	putbuf(buffer, size);
	            f->eax = size;
	        }
	        else
	        {
	            file = search_file(fd);
	            if(file == NULL)
	                f->eax = -1;
	            else
	                f->eax = file_write(file, buffer, size);
	        }
	      }
    	break;



      	case SYS_SEEK:
      //  printf("SEEK");
      		if(!is_valid((int*)f->esp + 2))
      			exit(-1);

      	    fd = *((int*)f->esp + 1);
       		position = (unsigned)(*((int*)f->esp + 2));
        	file = search_file(fd);

        	if(file != NULL)
          		file_seek(file, position);
        break;



    	case SYS_TELL:
       // printf("TELL");
    	//da el byte 
    	   	if(!is_valid((int*)f->esp + 1))
      			exit(-1);
		    fd = *((int*)f->esp + 1);
		    file = search_file(fd);
		    if(file == NULL)
		      f->eax = -1;
		    else
		      f->eax = file_tell(file);
        break;



    	case SYS_CLOSE:
        //printf("CLOSE");

	    	if(!is_valid((int*)f->esp + 1))
	      		exit(-1);
	    	fd = *((int*)f->esp + 1);
	    	file = search_file(fd);
		    if(file != NULL)
		    {
		      list_remove(&file->file_elem);
		      file_close(file);
		    }
		break;


    	default:
	    	exit(-1);
      	break;



    } //Switch end


}//syscall handler

static void exit(int status)
{
	printf("%s: exit(%d)\n", thread_current()->name, status);
  	thread_current()->mis_datos->return_state = status;
  	thread_exit();
}





	static bool is_valid(void *addr)
{
	bool ret = true;
	for(int i = 0; i < 4; i++)
	{
		if (!is_user_vaddr(addr))
		{
			ret = false;
			break;
		}
		else
			if(pagedir_get_page(thread_current()->pagedir, addr) == NULL)
			{
				ret = false;
				break;
			}
		addr++;
	}
	return ret;
}


static struct file * search_file(int fd)
{
	struct file *file = NULL;
	struct file *faux;
	struct list_elem *e = list_begin(&thread_current()->open_files);
	while(e != list_end(&thread_current()->open_files))
	{
		faux = list_entry(e, struct file, file_elem);
		if(faux->fd == fd)
		{
			file = faux;
			break;
		}
		else e = list_next(e);
	}
	return file;
}
//test
