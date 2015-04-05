/* Copyright (c) 2004-2006 Vlad Goncharov, Ruslan Staritsin
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */
 
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>

#include "win32.h"
#include "helper.h"

BOOL    g_console = TRUE;

static SERVICE_STATUS	ssStatus;       // current status of the service
static SERVICE_STATUS_HANDLE	sshStatusHandle;

static void     install_service(const char *config);        // NOTE: service depends on driver
static void     install_driver(const char *path);
static int     remove_service(const char *name);
static BOOL add_config_info(HANDLE schService, const char *config);

static VOID WINAPI service_main(DWORD dwArgc, LPTSTR *lpszArgv);
static VOID WINAPI service_ctrl(DWORD dwCtrlCode);

static BOOL ReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);

UINT
NtServiceIsRunning(LPCTSTR ServiceName)
{
	SC_HANDLE            schService;
	SC_HANDLE            schSCManager;
	DWORD                   RC;
	SERVICE_STATUS   ssStatus;
	UINT                        return_value;

	schSCManager = OpenSCManager(
		NULL,                   // machine (NULL == local)
		NULL,                   // database (NULL == default)
		SC_MANAGER_ALL_ACCESS   // access required
		);
		
	if (!schSCManager) 
		return -1;
	
	schService = OpenService(schSCManager, ServiceName, SERVICE_ALL_ACCESS);
	
	if (!schService) {
		RC = GetLastError();
		CloseServiceHandle(schSCManager);
		
		if (RC == ERROR_SERVICE_DOES_NOT_EXIST) 
			return -2;
		else 
			return -1;
	}
	
	QueryServiceStatus(schService, &ssStatus);
	
	if (ssStatus.dwCurrentState == SERVICE_RUNNING) 
		return_value = 1;
	else 
		return_value = 0;
		
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	
	return return_value;
}

int
wnd_main(int argc, char *argv[])
{
	int ss, retcode = 0;
	static SERVICE_TABLE_ENTRY dispatch_table[] = {
	    {SERVICE, service_main},
	    {NULL, NULL}
	};
	
	if (argc >= 2) {
		const char *param = argv[1];

		if (strcmp(param, "install") == 0) {
			if (argc < 3) {
                			fprintf(stderr, "Use: " SERVICE " install <startup-cmd-script>\n");
                			return -1;
            			}
                		install_service(argv[2]);
                		Sleep(500);
                		if (start(argv[2], FALSE)) {
                			stop();
            			};
            		}
            		else if (strcmp(param, "install_drv") == 0) {
			if (argc < 3) {
				fprintf(stderr, "Use: " SERVICE " install_drv <driver-path>\n");
				return -1;
			}
			install_driver(argv[2]);
		}
		else if (strcmp(param, "remove_drv") == 0) {
			retcode = remove_service(DRIVER);
		}
		else if (strcmp(param, "remove") == 0) {
			retcode = remove_service(SERVICE);
		}
		else if (strcmp(param, "enum") == 0)
			update_if_info(FALSE);
/*		
		else if (strcmp(param, "sysctl") == 0)
			sysctl_handler(argc, argv);
*/
		else {
			retcode = (orig_main(argc, argv));
		}
	} else {
		g_console = FALSE;
		
		ss =  NtServiceIsRunning(SERVICE);
		
		if (ss == 0) {
			// run as service
			fprintf(stderr, "Service is stopped. Try to run with parameters (ipfw -h)\n");
			if (!StartServiceCtrlDispatcher(dispatch_table))
				fprintf(stderr, "main: StartServiceCtrlDispatcher: %u\n", GetLastError());
		}
		else 
			orig_main(argc, argv);
		if (ss == -2)
			fprintf(stderr, "Warning! Service is not installed!\n");
	}
	
	return retcode;
}

void
install_service(const char *config)
{
	SC_HANDLE   schService;
	SC_HANDLE   schSCManager;
	CHAR szPath[MAX_PATH];

	if (GetModuleFileName(NULL, szPath, sizeof(szPath)) == 0) {
		fprintf(stderr, "install_service: GetModuleFileName: %u\n", GetLastError());
		return;
	}

	schSCManager = OpenSCManager(
	    NULL,                   // machine (NULL == local)
	    NULL,                   // database (NULL == default)
	    SC_MANAGER_ALL_ACCESS); // access required

	if (schSCManager != NULL) {
		schService = CreateService(
		   schSCManager,               // SCManager database
		   SERVICE,                    // name of service
		   SERVICE_DESCRIPTION,        // name to display
		   SERVICE_ALL_ACCESS,         // desired access
 		   SERVICE_WIN32_OWN_PROCESS,  // service type
		   SERVICE_AUTO_START,         // start type
		   SERVICE_ERROR_NORMAL,       // error control type
		   szPath,                     // service's binary
		   NULL,                       // no load ordering group
		   NULL,                       // no tag identifier
		   DRIVER "\0\0",              // dependencies
		   NULL,                       // LocalSystem account
		   NULL);                      // no password

		if (schService != NULL) {
			printf(SERVICE " service has been installed\n");
			 if (!add_config_info(schService, config))
                			fprintf(stderr, "Can't store config info! Service will use defaults.\n");
			CloseServiceHandle(schService);
		} else {
			fprintf(stderr, "install_service: CreateService: %u\n", GetLastError());
			DeleteService(schService);
		};

		CloseServiceHandle(schSCManager);
	} else
		fprintf(stderr, "install_service: OpenSCManager: %u\n", GetLastError());
}

void
install_driver(const char *szPath)
{
	SC_HANDLE   schService;
	SC_HANDLE   schSCManager;

	schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS); // access required

	if (schSCManager != NULL) {
		
		schService = CreateService(
		    schSCManager,               // SCManager database
		    DRIVER,                     // name of service
		    DRIVER_DESCRIPTION,         // name to display
		    SERVICE_ALL_ACCESS,         // desired access
		    SERVICE_KERNEL_DRIVER,      // service type
//		    SERVICE_SYSTEM_START,       // start type, for future
		    SERVICE_DEMAND_START,       // start type
		    SERVICE_ERROR_NORMAL,       // error control type
		    szPath,                     // service's binary
		    NULL,                       // no load ordering group
		    NULL,                       // no tag identifier
		    TEXT("IpFilterDriver") "\0\0",	// dependencies
		    NULL,                       // LocalSystem account
		    NULL);                      // no password

		if (schService != NULL) {
			printf(DRIVER " driver has been installed\n");
			CloseServiceHandle(schService);
		} else
			fprintf(stderr, "install_driver: CreateService: %u\n", GetLastError());

		CloseServiceHandle(schSCManager);
	}
	else
		fprintf(stderr, "install_driver: OpenSCManager: %u\n", GetLastError());
}

int
remove_service(const char *name)
{
	SC_HANDLE   schService;
	SC_HANDLE   schSCManager;

	schSCManager = OpenSCManager(
	    NULL,                   // machine (NULL == local)
	    NULL,                   // database (NULL == default)
	    SC_MANAGER_ALL_ACCESS); // access required
    
	if (schSCManager != NULL) {
		schService = OpenService(schSCManager, name, SERVICE_ALL_ACCESS);

		if (schService != NULL) {
			// try to stop the service
			if (ControlService(schService, SERVICE_CONTROL_STOP, &ssStatus)) {
				printf("stopping...");
				Sleep(1000);

				while (QueryServiceStatus( schService, &ssStatus)) {
					if (ssStatus.dwCurrentState == SERVICE_STOP_PENDING) {
						printf(".");
						Sleep( 1000 );
					} else
						break;
				}
                			printf("\n");

				if (ssStatus.dwCurrentState == SERVICE_STOPPED)
					printf("stopped\n");
				else
					printf("failed to stop\n");
			}

			// now remove the service
			if (DeleteService(schService))
				printf("service has been removed\n");
			else
				fprintf(stderr, "remove_service: DeleteService\n", GetLastError());

			CloseServiceHandle(schService);
	
		} else
			fprintf(stderr, "remove_service: OpenService: %u\n", GetLastError());

		CloseServiceHandle(schSCManager);
	} else
        		fprintf(stderr, "remove_service: OpenSCManager: %u\n", GetLastError());
        		
        	if (GetLastError() == 1062)
        		return 0;
        	else 
        		return GetLastError();
}

VOID WINAPI
service_main(DWORD dwArgc, LPTSTR *lpszArgv)
{
	HKEY hkey = NULL;
	char *config = NULL;
	unsigned int type, config_size, status;

	// register our service control handler:
	sshStatusHandle = RegisterServiceCtrlHandler(SERVICE, service_ctrl);
	if (sshStatusHandle == 0) {
		fprintf(stderr, "install_service: RegisterServiceCtrlHandler: %u\n", GetLastError());
		goto cleanup;
	}

	// SERVICE_STATUS members that don't change in example
	ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ssStatus.dwServiceSpecificExitCode = 0;

	// report the status to the service control manager.
	if (!ReportStatusToSCMgr(
	    SERVICE_START_PENDING, // service state
	    NO_ERROR,              // exit code
	    3000))                 // wait hint
		goto cleanup;
	
	    /* get config name from registry */

	if ((status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, CONFIG_SUBKEY, 0, KEY_QUERY_VALUE, &hkey)) != ERROR_SUCCESS) {
		SetLastError(status);
		fprintf(stderr, "RegOpenKeyEx: %u", status);
		goto cleanup;
	}

    if ((status = RegQueryValueEx(hkey, "config", 0, (DWORD *)&type, NULL, (DWORD *)&config_size)) != ERROR_SUCCESS) {
        SetLastError(status);
        fprintf(stderr, "RegOpenKeyEx: %u", status);
        goto cleanup;
    }

    if (type != REG_SZ) {
        fprintf(stderr, "Invalid type for config value in registry!\n");
        SetLastError(ERROR_INVALID_DATA);
        goto cleanup;
    }

    config = (char *)malloc(config_size);
    if (config == NULL) {
        perror("malloc");
        goto cleanup;
    }

    if ((status = RegQueryValueEx(hkey, "config", 0, NULL, config, (DWORD *)&config_size)) != ERROR_SUCCESS) {
        SetLastError(status);
        fprintf(stderr, "RegOpenKeyEx: %u", status);
        goto cleanup;
    }

	if (start(config, TRUE)) {
		
        	// start success
        	// report the status to the service control manager.
		if (!ReportStatusToSCMgr(
		    SERVICE_RUNNING,       // service state
		    NO_ERROR,              // exit code
		    0))                    // wait hint
			goto cleanup;
			
		wait();
		SetLastError(0);
	}
   
cleanup:
	    // try to report the stopped status to the service control manager.
	if (sshStatusHandle != 0)
		ReportStatusToSCMgr(SERVICE_STOPPED, GetLastError(), 0);
	 if (hkey != NULL)
        		RegCloseKey(hkey);
        		
    	free(config);
}

BOOL
ReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static unsigned int dwCheckPoint = 1;

	if (dwCurrentState == SERVICE_START_PENDING)
		ssStatus.dwControlsAccepted = 0;
	else
		ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	ssStatus.dwCurrentState = dwCurrentState;
	ssStatus.dwWin32ExitCode = dwWin32ExitCode;
	ssStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
		ssStatus.dwCheckPoint = 0;
	else
		ssStatus.dwCheckPoint = dwCheckPoint++;

	// Report the status of the service to the service control manager.
	if (!SetServiceStatus(sshStatusHandle, &ssStatus)) {
		fprintf(stderr, "install_service: SetServiceStatus: %u\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

VOID WINAPI
service_ctrl(DWORD dwCtrlCode)
{
	// Handle the requested control code.
	switch(dwCtrlCode) {
	// Stop the service.
	//
	// SERVICE_STOP_PENDING should be reported before
	// setting the Stop Event - hServerStopEvent - in
	// ServiceStop().  This avoids a race condition
	// which may result in a 1053 - The Service did not respond...
	// error.
	case SERVICE_CONTROL_STOP:
		ReportStatusToSCMgr(SERVICE_STOP_PENDING, NO_ERROR, 0); 
		// stop it!
		stop();
		return;

	// Update the service status.
	case SERVICE_CONTROL_INTERROGATE:
		break;

	// invalid control code
	default:
		break;
	}
	
	ReportStatusToSCMgr(ssStatus.dwCurrentState, NO_ERROR, 0);
}

BOOL
add_config_info(HANDLE schService, const char *config)
{
	BOOL result = FALSE;
	HKEY hkey = NULL;
	unsigned int status;

	if ((status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, CONFIG_SUBKEY, 0, KEY_SET_VALUE, &hkey)) != ERROR_SUCCESS) {
		SetLastError(status);
		fprintf(stderr, "RegOpenKeyEx: %u", status);
		goto done;
	}

	if ((status = RegSetValueEx(hkey, "config", 0, REG_SZ, config, strlen(config) + 1)) != ERROR_SUCCESS) {
		SetLastError(status);
		fprintf(stderr, "RegSetValueEx: %u", status);
		goto done;
	}

	result = TRUE;

done:
	if (hkey != NULL)
		RegCloseKey(hkey);
	return result;
}
