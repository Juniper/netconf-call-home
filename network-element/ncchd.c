/*****************************************************************************
Copyright (c) 2014-2016, Juniper Networks, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright 
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its 
   contributors may be used to endorse or promote products derived 
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.
 *****************************************************************************/



/*****************************************************************************
   OVERVIEW

   This file defines the `ncchd` daemon.  It's purpose is to read the
   system's current "running config" and then maintain connections to
   NMSs as specified in the configuration.  This code forks/execs `sshd`
   as soon as its TCP connection is accepted by the NMS.
 *****************************************************************************/


/*****************************************************************************
   INCLUDES AND EXTERNS
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>   // use -DNDEBUG compiler option to remove asserts
#include <fcntl.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include "roxml.h"
#include "ncchd.h"


/*****************************************************************************
   MACROS
 *****************************************************************************/

typedef unsigned int       bool;
#define true 1
#define false 0

#define PATH_SSHD "/usr/local/pkixssh-8.9/sbin/sshd"

// prints sshd's stderr to the screen, comment to direct
// output to the log file specified in the sshd_config file
#define DEBUG_SSHD


/*****************************************************************************
   LOCAL/STATIC DEFINITIONS
 *****************************************************************************/

static bool shutting_down = false; // only true if sigint delivered
static bool restarting    = false; // only true if sighup delivered


static void
signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("SIGINT CAUGHT!!! in pid 0x%x (ppid 0x%x)\n", getpid(), getppid());
        shutting_down = true;

    } else if (sig == SIGHUP) {

        printf("SIGHUP CAUGHT!!!\n");
        restarting = true;
        signal(SIGHUP, signal_handler);
    }
}


#ifdef DEBUG_SSHD
// this is simple utility to dump the Configuration structure to stdout
static void
print_config(Configuration* config) {
    uint8_t app_idx;
    for (app_idx=0; app_idx<config->num_apps; app_idx++) {
        Application* app = &(config->apps[app_idx]);
        printf("  - app %d\n", app_idx);
        printf("     - name = %s\n", app->name);
        printf("     - servers\n");
        uint8_t svr_idx;
        for (svr_idx=0; svr_idx<app->num_servers; svr_idx++) {
            Server* svr = &(app->servers[svr_idx]);
            printf("        - svr\n");
            printf("           - addr = %s\n", svr->addr);
            printf("           - port = %d\n", svr->port);
        }
        if (app->transport_type == SSH) {
            printf("     - transport: ssh\n");
            printf("        - host_keys\n");
            uint8_t key_idx;
            for (key_idx=0; key_idx<app->num_host_keys; key_idx++) {
                HostKey *host_key = &(app->host_keys[key_idx]);
                printf("           - host_key: %s\n", host_key->name);
            }
        } else {
            printf("     - transport: tls\n");
        }
        if (app->connection_type == PERSISTENT) {
            printf("     - connection_type = persistent\n");
            printf("          - keep_alive_strategy\n");
            printf("               - interval_secs = %d\n", app->keep_alive_strategy.interval_secs);
            printf("               - count_max = %d\n", app->keep_alive_strategy.count_max);

        } else {
            printf("     - connection_type = periodic\n");
            printf("        - timeout_mins = %d\n", app->periodic_connect_info.timeout_mins);
            printf("        - linger_secs = %d\n", app->periodic_connect_info.linger_secs);
        }
        printf("     - reconnect strategy\n");
        if (app->reconnect_strategy.start_with == FIRST_LISTED) {
            printf("          - starts_with = first_listed\n");
        } else {
            printf("          - starts_with = last_connected\n");
        }
        printf("          - interval_secs = %d\n", app->reconnect_strategy.interval_secs);
        printf("          - count_max = %d\n", app->reconnect_strategy.count_max);
    }
    printf("\n");
}
#endif


// This routine verifies values provided by the data access layer
static int // 0=OK, 1=ERROR
verify_incoming_config(Configuration *config) {

    uint8_t app_idx;
    for (app_idx=0; app_idx<config->num_apps; app_idx++) {
        Application* app = &(config->apps[app_idx]);

        if (app->transport_type == SSH) {
            uint8_t key_idx;
            for (key_idx=0; key_idx<app->num_host_keys; key_idx++) {
                HostKey *host_key = &(app->host_keys[key_idx]);

                // make sure file exists. Per the conf file passed into
                // OpenSSH, file neems to be in current directory
                struct stat stat_buf;
                if (stat(host_key->name, &stat_buf) != 0) {
                    printf ("HostKey file \"%s\" doesn't exist in current directory!\n",
                            host_key->name);
                    return 1;
                }
            }
        }

        if (app->transport_type == TLS) {
            printf("Sorry, the TLS transport type isn't supported yet...\n");
            return 1;
        }

        if (app->connection_type == PERIODIC) {
            printf("Sorry, the PERIODIC connection type isn't supported yet...\n");
            return 1;
        }
    }
    return 0;
}


// deep-free the Application structure
static void
free_application(Application* app) {
    int idx;
    for (idx=0; idx<app->num_host_keys; idx++) {
        free(&app->host_keys[idx]);
    }
    for (idx=0; idx<app->num_servers; idx++) {
        free(&app->servers[idx]);
    }
    free(app);
}



// deep-free the Configuration structure
static void
free_configuration(Configuration* config) {
    int app_idx;
    for (app_idx=0; app_idx<config->num_apps; app_idx++) {
        Application *app = &config->apps[app_idx];
        free_application(app);
    }
    free(config);
}



// This routine writes out an OpenSSH "sshd_config" file that is passed into
// `sshd` when it is executed.   This routine is NOT in data_access_layer.c
static int // 0=OK, 1=ERROR
set_sshd_config_file(Application *app) {
    FILE*  file;
    char   filename[32];
    char   buff[1024];

    sprintf(filename, ".%s.sshd_config_file", app->name);
    file = fopen(filename, "w");
    if (file == NULL) {
        return 1;
    }

    sprintf(buff,"UsePAM yes\n");
    fwrite(buff, strlen(buff), 1, file);

    sprintf(buff,"UsePrivilegeSeparation no\n");
    fwrite(buff, strlen(buff), 1, file);

    sprintf(buff,"ClientAliveInterval %d\n", 
                                      app->keep_alive_strategy.interval_secs);
    fwrite(buff, strlen(buff), 1, file);

    sprintf(buff,"ClientAliveCountMax %d\n", app->keep_alive_strategy.count_max);
    fwrite(buff, strlen(buff), 1, file);

    char cwd[512];
    getcwd(cwd, sizeof(cwd));
    sprintf(buff,"Subsystem netconf %s/netconfd\n", cwd);
    fwrite(buff, strlen(buff), 1, file);

    int      host_key_idx;
    for (host_key_idx=0; host_key_idx<app->num_host_keys; host_key_idx++) {
        HostKey* host_key;
        host_key = &(app->host_keys[host_key_idx]);
        sprintf(buff,"HostKey %s\n", host_key->name);
        fwrite(buff, strlen(buff), 1, file);
    }

    //sprintf(buff,"HostCertificate signed_cert.pem\n");
    //fwrite(buff, strlen(buff), 1, file);


    //sprintf(buff,"X509KeyAlgorithm x509v3-ecdsa-sha2-nistp384,sha384,ecdsa-sha2-nistp384\n");
    sprintf(buff,"X509KeyAlgorithm x509v3-ecdsa-sha2-nistp256,sha256,ecdsa-sha2-nistp256\n");
    fwrite(buff, strlen(buff), 1, file);

    fclose(file);
    return 0;
}


// return connected TCP socket for specified hostname, which
// may be a name or a v4/v6 address string
static int // -1=error, OK otherwise
connect_client(const char* hostname, uint16_t port) {
    struct addrinfo hints, *res, *ressave;
    int n, sockfd;
    char   port_str[16];

    sprintf(port_str, "%u", port);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    
    n = getaddrinfo(hostname, port_str, &hints, &res);
    if (n <0 ) {
        fprintf(stderr, "getaddrinfo error:: [%s]\n", gai_strerror(n));
        return -1;
    }

    ressave = res;

    sockfd=-1;
    while (res) {
        sockfd = socket(res->ai_family,
                        res->ai_socktype,
                        res->ai_protocol);

        if (!(sockfd < 0)) {
            if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
                break;

            close(sockfd);
            sockfd=-1;
        }
    res=res->ai_next;
    }

    freeaddrinfo(ressave);
    return sockfd;
}



// use forked proc to try to maintain a persistent connection to app...
static int // 0=ok, 1=error
connect_to_application(Application* app) {

    // fork a process so as to not block main thread 
    // from connecting to other apps...
  
    app->connecting_pid = fork();
    if (app->connecting_pid == -1) {
        printf("fork() failed\n");
        return 1;
    }
  
    if (app->connecting_pid != 0) {
        // this is the parent process
        return 0; // do nothing
    }
    // child process logic below
 
    // restore default signal handlers  (WORKING ON MAC?)
    if (signal(SIGINT, SIG_DFL) == SIG_ERR) {
        printf("signal() failed\n");
        return 1;
    }
    if (signal(SIGHUP, SIG_DFL) == SIG_ERR) {
        printf("signal() failed\n");
        return 1;
    }
  
    // continually try to connect 
    bool start_over = true;
    //while (1) {
    {
        uint8_t            retry_count;
        uint8_t            svr_idx=0;
        int                sockfd;

        // find server to connect to (svr_idx)
        if (start_over == true) {

            // toggle flag in case server connection fails
            start_over = false;

            if (app->reconnect_strategy.start_with == FIRST_LISTED) {
                // start with first server
                svr_idx = 0;
            } else {
                // must be LAST_CONNECTED, try to determine which it was/is

                PersistedState state;
                int            result;

                result = get_persisted_state(app->name, &state);
                if (result == 2) {
                    // no persisted state found, start with first server
                    svr_idx = 0;
                } else if (result == 1) {
                    printf("get_persisted_state(\"%s\") failed (ignoring)\n", app->name);
                    svr_idx = 0; // set as if no persisted state found
                } else {
                    // find the svr_idx having matching addr/port
                    for (svr_idx=0; svr_idx<app->num_servers; svr_idx++) {
                        if (memcmp(&(app->servers[svr_idx]), 
                                    &state.last_connected, sizeof(Server))==0) {
                            // found it!
                            break;
                        }
                    }
                    if (svr_idx == app->num_servers) {
                        // must have not been found, start with first
                        svr_idx = 0;
                    }
                }
            }

        } else {

            // try "next" server
            svr_idx++;
            if (svr_idx == app->num_servers) {
                // end of list, loop back to '0'
                svr_idx = 0;
            }

        }

        // got the svr_idx to try to connect to, do it now...
        retry_count = 0;
        while (retry_count < app->reconnect_strategy.count_max) {

            // addr can a be hostname or v4/v6 addess string
            sockfd = connect_client(app->servers[svr_idx].addr,
                                    app->servers[svr_idx].port);
            if (sockfd == -1) {
                printf("connect failed...\n");

                // connect failed
                if (retry_count == app->reconnect_strategy.count_max) {
                    break;
                } else {
                    retry_count++;
                    sleep(app->reconnect_strategy.interval_secs);
                }

            } else {   // connect succeeded
                PersistedState state;
                int            result;
                pid_t          pid;
                pid_t          retpid;
                int            status;

                // set persisted state
                assert(sizeof(PersistedState) == sizeof(Server));
                memcpy(&state, &(app->servers[svr_idx]), sizeof(Server));
                result = set_persisted_state(app->name, &state);
                if (result == 1) {
                    printf("set_persisted_state(\"%s\") failed (ignoring)\n", app->name);
                }

                // fork exec sshd 
                // FIXME: TLS-based transport logic should be added here
                if ((pid = fork()) == 0) { // child to exec sshd
                    char sshd_config_filename[64];
      
                    // write out the app's config-file
                    if (set_sshd_config_file(app) != 0) {
                        printf ("set_sshd_config_file(%s) failed\n", app->name);
                        exit(1);  // just the child process exits
                    }

                    // store config filename in a var
                    sprintf(sshd_config_filename, ".%s.sshd_config_file", 
                                                  app->name);



                    // dup stdin/stdout/stderr for reading/writing the client
                    if (dup2(sockfd, 0) == -1) {
                        printf("dup2(sockfd, 0) failed\n");
                        exit(1);  // just the child process exits
                    }
                    if (dup2(sockfd, 1) == -1) {
                        printf("dup2(sockfd, 1) failed\n");
                        exit(1);  // just the child process exits
                    }
#ifndef DEBUG_SSHD
                    if (dup2(sockfd, 2) == -1) {
                        printf("dup2(sockfd, 2) failed\n");
                        exit(1);  // just the child process exits
                    }
                    execl(PATH_SSHD, PATH_SSHD, "-i", "-f",
                                                sshd_config_filename, NULL);
#else
                    execl(PATH_SSHD, PATH_SSHD, "-ddd", "-e", "-i", "-f", 
                                                sshd_config_filename, NULL);
#endif

                    // logic should never get here
                    assert(0);  // ok for -DNDEBUG to remove

                } // end child fork

                // this is the parent
                retpid = waitpid(pid, &status, 0); // wait for child process to end
                if (retpid != pid) {
                    if (retpid == -1) {
                        printf("errno(%d) [%s]\n", errno, strerror(errno));
                    } else {
                        printf("pid != retpid (%d)\n", retpid);
                        if (WIFCONTINUED(status)) printf("WIFCONTINUED\n");
                        if (WIFEXITED(status)) printf("WIFEXITED\n");
                        if (WIFSIGNALED(status)) printf("WIFSIGNALED\n");
                        if (WIFSTOPPED(status)) printf("WIFSTOPPED\n");
                    }
                }
                close(sockfd);
                break;
            }
        } // end while trying to connect to server

        if (retry_count < app->reconnect_strategy.count_max) {
            // we were connected to something, what we connect to next is
            // driven by the reconnect_strategy.start_with value...
            start_over = true;
        }

    } // end while(1)

    // logic never gets here
    assert(0);  // OK for -DNDEBUG to compile out
    return 1;
}




// PSEUDOCODE
//   for each app in active
//       if also in incoming
//           - do not disconnect, just copy it's pid into incoming
//       else
//           - disconnect it
//   copy all the incoming app pointers to active
//   for each app in "new" active
//       if pid not set
//           - connect app
static int // 0=OK, 1=ERROR
apply_incoming_config(Configuration* active, Configuration* incoming) {
    int          incoming_app_idx;
    int          active_app_idx;
    Application* incoming_app;
    Application* active_app;

    // iterate over apps in active
    for (active_app_idx=0; active_app_idx<active->num_apps; active_app_idx++) {

        active_app = &(active->apps[active_app_idx]);
        assert(active_app->connecting_pid != -1);

        // see if it's also in the incoming config
        for (incoming_app_idx=0; incoming_app_idx<incoming->num_apps; incoming_app_idx++) {

            incoming_app = &(incoming->apps[incoming_app_idx]);

            // match only if *entire* definition (not including pid) is
            // the same (too conservative?)
            if (memcmp(incoming_app, active_app, sizeof(Application)-sizeof(pid_t)) == 0) {
                // found it, just copy its pid to the incoming struct
                incoming_app->connecting_pid = active_app->connecting_pid;
                active_app->connecting_pid = -1;
                break;  // no need to keep looking for it
            }
        }

        // if app was NOT found, disconnect it
        if (incoming_app_idx == incoming->num_apps) {
            // app not found in incoming, disconnect it
            kill(active_app->connecting_pid, SIGKILL);
            active_app->connecting_pid = -1;
        }

#ifdef DEBUG_SSHD
        // one way or the other, the pid should now be -1
        assert(active_app->connecting_pid == -1);
#endif

        // free this active app's memory
        free_application(active_app);
    }

    // copy all the incoming app pointers to active
    memcpy(active, incoming, sizeof(Configuration));

    // iterate over apps in "new" active, for those with no PID
    for (active_app_idx=0; active_app_idx<active->num_apps; active_app_idx++) {
        active_app = &(active->apps[active_app_idx]);

        // ensure app isn't already connected
        if (active_app->connecting_pid != -1) {
            break;  // nothing to do
        }

        // connect to this app now
        int result = connect_to_application(active_app);
        if (result != 0) {
            printf("could not fork process to connect app \"%s\"\n", active_app->name);
            return 1;
        }
    }
    return 0;
}


/*****************************************************************************
   MAIN
 *****************************************************************************/


// returns 0 on graceful shutdown; 1 otherwise 
int main(int argc, char* argv[]) {
    Configuration* active_config;
    Configuration* incoming_config;
    int            result;
    int            app_idx;


    // register handler for graceful shutdown 
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
      printf("signal() failed\n");
      return 1;
    }

    // register handler to reload config
    if (signal(SIGHUP, signal_handler) == SIG_ERR) {
      printf("signal() failed\n");
      return 1;
    }

    // alloc active-config.  Outside while-loop below since
    // handle persists across HUPs
    active_config  = (Configuration*)calloc(1, sizeof(Configuration));
    if (active_config == NULL) {
      printf("could not alloc Configuration\n");
      return 1;
    }

    // exit on SIGINT, loop on SIGHUP
    while (shutting_down == false) {

        // alloc incoming-config
        incoming_config  = (Configuration*)calloc(1, sizeof(Configuration));
        if (incoming_config == NULL) {
            printf("could not alloc Configuration\n");
            sleep(5); 
            continue;    // try again ad infinitum
        } 

        // fetch and verify latest config from system
        result = get_incoming_config(incoming_config);
        if (result != 0) {
            printf("get_incoming_config() failed\n");
            free(incoming_config);
            sleep(5); 
            continue;    // try again ad infinitum
        }
#ifdef DEBUG_SSHD
        print_config(incoming_config);
#endif
        result = verify_incoming_config(incoming_config);
        if (result != 0) {
            printf("verify_incoming_config() failed\n");
            free_configuration(incoming_config);
            sleep(5); 
            continue;    // try again ad infinitum
        }

        // activate the incoming config (kill/fork procs as needed)
        result = apply_incoming_config(active_config, incoming_config);
        if (result != 0) {
            printf("apply_incoming_config() failed\n");
            free_configuration(incoming_config);
            sleep(5); 
            continue;    // try again ad infinitum
        }

        // don't need this anymore
        free_configuration(incoming_config);

        // sleep until either SIGINT or SIGHUP delivered
        while (shutting_down==false && restarting==false) {
            sleep(300);
        }

        // reset SIGHUP flag for next loop, if needed
        if (restarting == true) {
            restarting = false;
        }
    }

    // if logic gets here, SIGINT signal must have been received

    // shutting down - kill children
    for (app_idx=0; app_idx<active_config->num_apps; app_idx++) {
        Application *active_app;
        active_app = &active_config->apps[app_idx];
        if (active_app->connecting_pid != -1) {
            kill(active_app->connecting_pid, SIGKILL);
        }
    }

    // release memory
    free_configuration(active_config);

    return 0; // clean exit
}



