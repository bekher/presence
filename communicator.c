/* Presence Kernel Rootkit Dectection Suite -
 * Demonstrative Implementation for Intel ISEF 2012
 *
 * Copyright Gregory Bekher 2012. Only author is
 * authorized use of this software.
 *
 * Communicator.c (usrcom): daemon to mointor the
 * status of the Presence core. Provides a link
 * between the kernel and userspace tools. This
 * program monitors the procfile specified in
 * comlink.h to report the status of the kernel
 * scanner. This tool will invoke the cleanup
 * script defined in comlink.h once a rootkit has
 * been found.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "include/comlink.h"
#include "include/config.h"

int main(){

	printf("\nPresence Userspace Tools Copyright Gregory Bekher 2012 \n");

	char * msg 	= (char *)malloc(512);
	char * filename = (char *)malloc(64);

	strcpy(filename, "/proc/");

	strcat(filename, PROCFS_NAME);

	strcpy(msg, "Error: can't read procfile, no contents\n\0");

        char line[512];

	int time;

	_kmam_status status = KMAM_STATUS_SAFE;
	for( time = 0; ; time++){
		FILE * file = fopen(filename, "r");

	if(file == NULL){
		printf("\nComlink error: Can't open /proc file %s\nExiting\n\0", PROCFS_NAME);
		exit(-1);
	}


	        while (fgets(line, sizeof(line), file)) {
			strcpy(msg, line);

			if( strstr(msg, ST_CLEAR) )
				status = KMAM_STATUS_SAFE;

			else{
				status = KMAM_STATUS_ALARM;

				printf("\nWARNING, Presence discovered kernel-level hooks!\n");
				printf("\nRunning %s to clean system \nOutput of clean script:\n\n", UL_CLEAN_SCRIPT);

				system(UL_CLEAN_SCRIPT);
			}

		}

			fclose(file);

		//printf("%s",msg);

		sleep(5);
	}


	free(msg);

	free(filename);

	return 0;

}
