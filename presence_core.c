/* Presence Kernel Rootkit Dectection Suite -
 * Demonstrative Implementation for Intel ISEF 2012
 *
 * Copyright Gregory Bekher 2012. Only author is
 * authorized use of this software.
 *
 * Presence_Core.c: Core kernel module designed for
 * the Presence PoC suite.
 */

/* KMAM: Kernel Memory Address (Hooking) Monitor
 * Changelog:
 * v0.2 	Nov 29th 	Working version with arrays of nodes
 * v0.21 	Nov 30th	Includes IDT detection. Partial implementation of function byte checking
 * v0.3         Mar 3rd		Cleaned up code, performance tweaks, bytechecking optional
 * v0.4		Apr 7th		Added communication between userspace tools and kernel tools
 * v0.41	TBD		Clean up code, add comments & whitespace
 */

/////

//System headers

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <net/tcp.h>

//Local configuration headers

#include "include/config.h"
#include "include/comlink.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gregory Bekher");

//Number of syscall nodes to be allocated
#define KMAM_MAX_SYSCALLS_CHECK NR_syscalls
#define MAX_ADDR	500
#define MAX_TOTAL	200+500

#define KMAM_VERSION 	"0.4"
#define KMAM_TITLE   	"Presence Core v0.4"
#define KMAM_NAME	"scmon_0_X"

#define KMAM_DO__CHECK_IDT 1

#ifndef KMAM_DO__PROTECT_DELETION
//I wouldn't change this to 1 unless you have a death wish
#define KMAM_DO__PROTECT_DELETION 0

#endif

#define KMAM_MAX_SC_BYTECHECK 256

#define KMAM_DO__BYTECHECK 0 //Very buggy leave at 0

#define KMAM_E_MEMSET -1

#define IDTCHECK 200

/* Removing read/write protection retrieved from
 * http://memset.wordpress.com/2011/01/20/syscall-hijacking-
 * dynamically-obtain-syscall-table-address-kernel-2-6-x/
 */

#define FORCE_READ_WRITE()  write_cr0 (read_cr0 () & (~ 0x10000))
#define FORCE_READ_ONLY()  write_cr0 (read_cr0 () | 0x10000)

static int kmam_global_status;

unsigned long idtlocs[IDTCHECK];
unsigned long * idttable;

struct baseline_node{
	unsigned int original_value;
	int dofix; //bool
	int times_detected;
	int max_detected;
	int report_hook;
	char first_bytes[KMAM_MAX_SC_BYTECHECK+5];
	int bytes_checked;
} baseline_nodes[KMAM_MAX_SYSCALLS_CHECK+20];

unsigned int values_of_syscall_locs[KMAM_MAX_SYSCALLS_CHECK+20];

unsigned long get_addr_idt (void)
 {
/* http://www.phrack.org/archives/59/p59_0x04_Handling%20the%2
 * 0Interrupt%20Descriptor%20Table_by_kad.txt */

         unsigned char idtr[6];
         unsigned long idt;
        __asm__ volatile ("sidt %0": "=m" (idtr));
        idt = *((unsigned long *) &idtr[2]);
        return(idt);
 }

typedef unsigned int hex;

//Syscall table locations
unsigned int *syscall_table = (unsigned int *) SYSCALL_TABLE;

int done, i, j;

unsigned int original_value[100];

//The below two functions check the interrupt table descriptor vector addresses
static asmlinkage int setidt(void){
        for(i=0;i<IDTCHECK;i++) idtlocs[i]=idttable[i];
        return 0;
}
static asmlinkage int checkidt(void){
        for(i=0;i<IDTCHECK;i++){
        if(idttable[i]!=idtlocs[i])printk(KERN_ALERT "IDT ERROR AT %d\n", i);
        }
        return 0;
}
//Begin syscall table checking functions
static asmlinkage int set_node(void){
		unsigned long *  writefuncs = (unsigned long *) NULL;
        	char writefuncinfos 	    = (unsigned long *) NULL;

        for(i=0;i<KMAM_MAX_SYSCALLS_CHECK;i++){
                baseline_nodes[i].original_value = syscall_table[i];
                baseline_nodes[i].dofix		 = 0;
                baseline_nodes[i].times_detected = 0;
                baseline_nodes[i].max_detected	 = 1;
		baseline_nodes[i].report_hook	 = KMAM_STATUS_SAFE;

	if(KMAM_DO__BYTECHECK==1){

		baseline_nodes[i].bytes_checked	 = 0;

		writefuncs = (unsigned long *) syscall_table[i];
                writefuncinfos = *writefuncs;

                for(j=0;j<KMAM_MAX_SC_BYTECHECK;i++){

                        if(!(*writefuncs)) continue;

                        writefuncs=writefuncs + j;//increment 1 byte from an address. eg: was addr 0x0900, now is 0x0901
                        writefuncinfos = *writefuncs;

			baseline_nodes[i].first_bytes[j]=(char)writefuncinfos;
			baseline_nodes[i].bytes_checked++;

                        //printk(KERN_ALERT "Address: %x, value of address as char: %c", (hex)writefuncs, (char)writefuncinfos);
                }
}
        }
        return 0;
}

static asmlinkage int check_node(void){

        unsigned long *  writefuncs = (unsigned long *)  NULL;
        char writefuncinfos 	    = (unsigned long *) NULL;

        for(i=0;i<KMAM_MAX_SYSCALLS_CHECK;i++){

	        if(baseline_nodes[i].original_value!=syscall_table[i]){

        	        baseline_nodes[i].times_detected++;
			baseline_nodes[i].report_hook = KMAM_STATUS_ALARM;
			kmam_global_status = KMAM_STATUS_ALARM;

                	printk(KERN_ALERT "ALERT SYSCALL %i HAS BEEN HOOKED!!!\n", i);

               		if(baseline_nodes[i].times_detected>=baseline_nodes[i].max_detected) {
             			printk(KERN_ALERT "Attempting to repair system call %d...\n", i);

                        	FORCE_READ_WRITE();

                        	syscall_table[i] = baseline_nodes[i].original_value;

				FORCE_READ_ONLY();
			}
		}

	if(KMAM_DO__BYTECHECK ==1) {

		writefuncs = syscall_table[i];

                writefuncinfos = *writefuncs;

                for(j=0;j<KMAM_MAX_SC_BYTECHECK;i++){

                        if(!(*writefuncs)) continue;

                        writefuncs = writefuncs + j;//increment 1 byte from an address. eg: was addr 0x0900, now is 0x0901

                        writefuncinfos = *writefuncs;

                        if(baseline_nodes[i].first_bytes[j]!=(char)writefuncinfos){

                                baseline_nodes[i].times_detected++;

                       		printk(KERN_ALERT "ALERT SYSCALL %i HAS BEEN HOOKED!!!\n", i);

                        		if(baseline_nodes[i].times_detected>=baseline_nodes[i].max_detected) {

                                		printk(KERN_ALERT "Attempting to repair system call %d...\n", i);

                                		FORCE_READ_WRITE();

                                		syscall_table[i]=baseline_nodes[i].original_value;

                                		FORCE_READ_ONLY();

                        		}

					else

				printk(KERN_ALERT "ALERT this system call has been rehooked at least \
		%d times therefore, no more repair attempts will be made.");

			}
                        //printk(KERN_ALERT "Address: %x, value of address as char: %c", (hex)writefuncs, (char)writefuncinfos);
                }
	}
	}
	return 0;
}
//End syscall table hooking check
//Begin TCP /proc descriptor proof-of-concept detection
struct proc_db_fnptr{
	unsigned long * function_loc;
	int times_accessed;
};

//Database of function pointers to proc file operations specifically for the
//TCP entry. There is only one database node for TCP as this is a PoC.
struct proc_db_fnptr tcp_spoof_loc;

//Below based on tcp port spoofer in IPSECS Kernel Beast
/* Flags for get_tcp_ops_fn: 0 is to simply return address. 1 is to fix address */

#define KMAM_GET_TCP_OPS_FN_FLAGS__GET 0
#define KMAM_GET_TCP_OPS_FN_FLAGS__FIX 1

int tcpinfo_status;

static asmlinkage unsigned long * get_tcp_ops_fn(int flags, unsigned long * org_loc){

	struct proc_dir_entry * find_proc_dir_entry =  init_net.proc_net->subdir;

	struct tcp_seq_afinfo * org_afinfo = NULL;

	while (strcmp(find_proc_dir_entry->name, "tcp"))

                find_proc_dir_entry = find_proc_dir_entry->next;

          if((org_afinfo = (struct tcp_seq_afinfo*)find_proc_dir_entry->data)){

                if(flags==KMAM_GET_TCP_OPS_FN_FLAGS__FIX){

			org_afinfo->seq_ops.show = org_loc;

			tcpinfo_status = KMAM_STATUS_ALARM;

		}

		return (unsigned long *) org_afinfo->seq_ops.show;

        }

	return KMAM_E_MEMSET;
}

static asmlinkage int set_proc_opfunc_db(void){
	tcp_spoof_loc.function_loc = get_tcp_ops_fn(NULL, NULL);
	return 0;
}
static asmlinkage int checkfix_opfun_db(void){
	if(tcp_spoof_loc.function_loc != get_tcp_ops_fn(NULL, NULL)){
	printk(KERN_ALERT "WANRING TCP INFO FUNCTION (SEQ_OPS) FOR /PROC OUTPUT COMPROMISED\n Repairing\n");
		get_tcp_ops_fn(KMAM_GET_TCP_OPS_FN_FLAGS__FIX, tcp_spoof_loc.function_loc);
	}
	return 0;
}

// End TCP /proc hook detector
struct task_struct *  check_looper;

//#define DEBUG__
//The loop that gets called perodically by the kernel timer
static asmlinkage void loop_mon(void * data){
	unsigned long *  writefuncs= syscall_table[__NR_write];

	char writefuncinfos = * writefuncs;

        do{

#ifdef DEBUG__
		printk(KERN_ALERT "System call table addr: %x, addr of addr is %x", (hex)syscall_table, (hex)*syscall_table);
                printk(KERN_ALERT "\nCurrent value in memory of the write command: \n");
		writefuncs = syscall_table[__NR_write];
		writefuncinfos = *writefuncs;
		for(i=0;i<120;i++){
			if(!(*writefuncs)) continue;
			writefuncs=writefuncs + i;
			writefuncinfos = *writefuncs;
			printk(KERN_ALERT "Address: %x, value of address as char: %c", (hex)writefuncs, (char)writefuncinfos);
		}
		printk(KERN_ALERT "\n Reached null value in memory\n");
#endif

		checkidt();

		checkfix_opfun_db();

		check_node();

                //Set task state to interruptible sleep

                set_current_state(TASK_INTERRUPTIBLE);

                schedule_timeout(KMAM_SCAN_RATE_SEC*HZ);

        } while(!done && !kthread_should_stop());

}
//End loop

//Begin anti-deletion procedures:
asmlinkage int (*org_delete_module)(const char __user *, unsigned int);

asmlinkage int kmam_delete_module(const char __user *name_user, unsigned int flags){

	char *mod_name=(char*)kmalloc(256,GFP_KERNEL);

 	copy_from_user(mod_name,name_user,255);

	int ret;

  	if(strstr(mod_name,KMAM_NAME))
    		return -EACCES;
 	else
		ret = (*org_delete_module)(name_user, flags);

	kfree(mod_name);

	return ret;
}
//End anti-deletion hook

//Begin userspace tools communication functions:

#ifdef KMAM_DO__COM
struct proc_dir_entry *proc_file;

static void *kmam_seq_start (struct seq_file * seq_file, loff_t *pos ) {

	static unsigned long count = 0;

	//New Sequence
	if( *pos == 0 ) {
		//return a  non null value to start the sequence
		return &count;
	}

	//else, it's the end of the sequence, set end and return null to stop reading
	*pos = 0;
	return NULL;

}

static void *kmam_seq_next (struct seq_file * sfile, void * vd, loff_t *pos) {

	unsigned long *tmp_vd = (unsigned long *) vd;
	(*tmp_vd)++;
	(*pos)++;
	return NULL;
}

static void kmam_seq_stop (struct seq_file * sfile, void *vd){
	//Nil
}

static int kmam_seq_show(struct seq_file * sfile, void * vd){
	loff_t * seq_pos = (loff_t*) vd;
	char * output = (char*)kmalloc(512,GFP_KERNEL);

	/* No time tonight to write something to get this done dynamically,
	* and for the sake of time I'm going to explain this breifly: I
	* built a reporting system to generate output to a proc file which
	* userland can access to determine the status of the system. From
	* there, what happens, this scanner module doens't care. However,
	* for each reportable hooked function--in this proof of concept
	* only syscalls--the code below will append an alert to the proc
	* file. To generate this, I'm using a quick if statement survey.
	* TODO: turn this survey into a dynamically mangageble database.
	*/

	if (kmam_global_status == KMAM_STATUS_SAFE ) {

		strcpy(output, ST_CLEAR);

	}

	else {

		if(baseline_nodes[__NR_write].report_hook == KMAM_STATUS_ALARM){

			strcat(output, ST_WRITE);
			baseline_nodes[__NR_write].report_hook = KMAM_STATUS_SAFE;
		}
                if(baseline_nodes[__NR_read].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_READ);
			baseline_nodes[__NR_read].report_hook = KMAM_STATUS_SAFE;


                }
                if(baseline_nodes[__NR_open].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_OPEN);
			baseline_nodes[__NR_open].report_hook = KMAM_STATUS_SAFE;

                }
                if(baseline_nodes[__NR_exit].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_EXIT);
			baseline_nodes[__NR_exit].report_hook = KMAM_STATUS_SAFE;

                }

                if(baseline_nodes[__NR_unlink].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_UNLINK);
			baseline_nodes[__NR_unlink].report_hook = KMAM_STATUS_SAFE;

                }
                if(baseline_nodes[__NR_unlinkat].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_UNLINKAT);
			baseline_nodes[__NR_unlinkat].report_hook = KMAM_STATUS_SAFE;

                }
                if(baseline_nodes[__NR_close].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_CLOSE);
			baseline_nodes[__NR_close].report_hook = KMAM_STATUS_SAFE;

                }
                if(baseline_nodes[__NR_rmdir].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_RMDIR);
			baseline_nodes[__NR_rmdir].report_hook = KMAM_STATUS_SAFE;

                }
                if(baseline_nodes[__NR_rename].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_RENAME);
			baseline_nodes[__NR_rename].report_hook = KMAM_STATUS_SAFE;

                }
                if(baseline_nodes[__NR_delete_module].report_hook == KMAM_STATUS_ALARM){

                        strcat(output, ST_DELETE_MODULE);
			baseline_nodes[__NR_delete_module].report_hook = KMAM_STATUS_SAFE;

                }
                if(tcpinfo_status ==  KMAM_STATUS_ALARM){

                        strcat(output, ST_TCPAFINFO);
			tcpinfo_status = KMAM_STATUS_SAFE;

                }
		kmam_global_status = KMAM_STATUS_SAFE;

	}

	strcat(output, ST_END);

	seq_printf(sfile, output);

	kfree(output);

	return 0;
}


static int get_hook_status(char * output){
	int ret_val;
	//This is the function to dynamically generate reports
	//This is on the TODO list.
}

static struct seq_operations kmam_seq_ops = {
	.start	= kmam_seq_start,
	.next	= kmam_seq_next,
	.stop	= kmam_seq_stop,
	.show	= kmam_seq_show
};

static int proc_open(struct inode *inode, struct file *file) {
	return seq_open(file, &kmam_seq_ops);
};

static const struct file_operations proc_file_fops = {

	.owner   = THIS_MODULE,
 	.open	 = proc_open,
 	.read	 = seq_read,
 	.llseek  = seq_lseek,
 	.release = seq_release

};

#endif

//Begin install/uninstall functions

int kmam_install(void)
{
	printk(KERN_ALERT "***\nLoading %s version %s...\n",
		KMAM_TITLE ,KMAM_VERSION);

	printk(KERN_ALERT "Presence Core Copyright Gregory Bekher 2012 \n");

	kmam_global_status = KMAM_STATUS_SAFE;
	tcpinfo_status 	   = KMAM_STATUS_SAFE;

	if(KMAM_DO__PROTECT_DELETION){ //Anti-deletion

		FORCE_READ_WRITE();

		org_delete_module = (void *)syscall_table[__NR_delete_module];
		syscall_table[__NR_delete_module] = kmam_delete_module;

		FORCE_READ_ONLY();
	}

#ifdef KMAM_DO__COM

	proc_file = proc_create(PROCFS_NAME, 0, NULL, &proc_file_fops);

	if(proc_file == NULL) {

		remove_proc_entry(PROCFS_NAME, NULL);
		printk(KERN_ALERT "KMAM START ERROR: Cannot create proc com link \
@ /proc/%s\nWill continue startup\n", PROCFS_NAME);
	}

	printk(KERN_ALERT "Presence KMAM comlink established \n");
#endif

	//Setup
	idttable  = (unsigned long)get_addr_idt();
	setidt();

	set_proc_opfunc_db();

	done = 0;

	//Invoke kthread
	check_looper = kthread_run( (void *)loop_mon,
			NULL , "pres_kmam_looper_thread");

	if(!check_looper) return -1;

	set_node();

	printk(KERN_ALERT "Your system is now secure against \
kernel rootkits...\n***\n");

	return 0;
}

void kmam_clean(void)
{
	printk(KERN_ALERT "\nWARNING %s SECURITY MODULE IS BEING REMOVED!!\n\
Disregard this message if administrator is removing module. \n\
OTHERWISE CONSIDER THIS AN ATTACK ON YOUR SYSTEM\n", KMAM_TITLE );

	//Stop kthread
	kthread_stop(check_looper);

	if(KMAM_DO__PROTECT_DELETION){
		FORCE_READ_WRITE();
		syscall_table[__NR_delete_module] = org_delete_module;
		FORCE_READ_ONLY();
	}

#ifdef KMAM_DO__COM
	remove_proc_entry(PROCFS_NAME, NULL);
	printk(KERN_ALERT "Uninstalled proc com file for %s\n", KMAM_TITLE );
	done=1;
#endif
}

module_init(kmam_install);
module_exit(kmam_clean);

