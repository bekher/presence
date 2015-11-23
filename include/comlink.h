/* Presence Kernel Rootkit Dectection Suite -
 * Demonstrative Implementation for Intel ISEF 2012
 *
 * Copyright Gregory Bekher 2012. Only author is
 * authorized use of this software.
 *
 * Comlink.h: definitons shared between the
 * communication daemon and the kernel scanner
 */

#ifndef KMAM_COMLINK_H
#define KMAM_COMLINK_H

#define KMAM_DO__COM

#define ST_CLEAR  	 "s00 "
#define ST_WRITE  	 "s01 "
#define ST_READ 	 "s02 "
#define ST_OPEN 	 "s04 "
#define ST_CLOSE 	 "s05 "
#define ST_EXIT		 "s06 "
#define ST_UNLINK 	 "s07 "
#define ST_UNLINKAT 	 "s08 "
#define ST_RMDIR 	 "s09 "
#define ST_RENAME 	 "s10 "
#define ST_DELETE_MODULE "s11 "
#define ST_TCPAFINFO 	 "s12 "
#define ST_OTHER_HOOK 	 "s0? "
#define ST_END		 "\n\0"

typedef int _kmam_status;

#define KMAM_STATUS_SAFE  0
#define KMAM_STATUS_ALARM -1

#define PROCFS_NAME "kmam_procfs"

//#define UL_CLEAN_SCRIPT ". ~/rootkittesting/communicator/dummy.sh"

#endif
