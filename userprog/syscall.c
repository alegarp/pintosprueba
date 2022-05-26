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

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if(!is_valid(f->esp))
  	exit(-1);

  int syscall_code = *(int*)f->esp;
  if(syscall_code == SYS_HALT)
  {
  	shutdown_power_off();
  }
