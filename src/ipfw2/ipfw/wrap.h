#ifndef _WIN32WRAP_H_
#define _WIN32WRAP_H_

int
main(int ac, char *av[])
{
	WSADATA ws;
	int errcode = 0;

	WSAStartup(MAKEWORD(2,0), &ws);

#define main	orig_main
	
	errcode = wnd_main(ac, av);
	
	WSACleanup();
	exit(errcode);
}

#endif /* _WIN32WRAP_H_ */
