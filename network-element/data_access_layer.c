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

  The functions listed in this file are used to read/write data to the 
  system.  As each target environment may have a different persistence
  tier, it is expected these routines will be replaced with deployment-
  specific logic.

  The current implementation uses two files:

    config.xml - the system's current "running" config
    .<app_name>.state - the persisted operational state for the named app

 *****************************************************************************/


/*****************************************************************************
   INCLUDES AND EXTERNS
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>    // use -DNDEBUG compiler option to remove asserts
#include <errno.h>
#include <unistd.h>
#include "roxml.h"
#include "ncchd.h"


/*****************************************************************************
   CUSTOMIZABLE DEFINITIONS (modify these for your runtime enviroment)
 *****************************************************************************/

// This routine returns the system's current configuration, same as a
// NETCONF server's "running" datastore.  The routine is executed once
// on startup and again for each SIGHUP
int  // 0 on success, 1 on error
get_incoming_config(Configuration* incoming_config) {

    // This reference implementation simply reads the configuration 
    // from a local file called "config.xml" and builds an C-based
    // in-memory datastructure.

    node_t *root = roxml_load_doc("config.xml");
    node_t *cur_node;
    cur_node = roxml_get_chld(root, NULL, 0);      // <netconf>
    cur_node = roxml_get_chld(cur_node, NULL, 0);  // <call-home>
    cur_node = roxml_get_chld(cur_node, NULL, 0);  // <applications>

    incoming_config->num_apps = roxml_get_chld_nb(cur_node);
    incoming_config->apps = (Application*)calloc(incoming_config->num_apps, sizeof(Application));
    if (incoming_config->apps == NULL) {
        printf("could not alloc apps struct\n");
        roxml_release(RELEASE_ALL);
        roxml_close(root);
        return 1;
    }

    int app_idx;
    for (app_idx=0; app_idx<roxml_get_chld_nb(cur_node); app_idx++) {

        Application *app = &(incoming_config->apps[app_idx]);

        node_t *cur_app_node = roxml_get_chld(cur_node, NULL, app_idx);
        assert(strcmp(roxml_get_name(cur_app_node, NULL, 0), "application")==0);


        // init defaults (from YANG module definition)
        app->connection_type = PERSISTENT;
        app->reconnect_strategy.start_with = FIRST_LISTED;
        app->reconnect_strategy.interval_secs = 5;
        app->periodic_connect_info.timeout_mins = 5;
        app->periodic_connect_info.linger_secs = 30;
        app->keep_alive_strategy.interval_secs = 15;
        app->keep_alive_strategy.count_max = 3;

        // init "operational state"
        app->connecting_pid = -1;

        // now parse DOM, filling in mandatory attributes and 
        // potentially overriding defaults

        int chld_idx;
        for (chld_idx=0; chld_idx<roxml_get_chld_nb(cur_app_node); chld_idx++) {
            node_t *cur_chld_node =roxml_get_chld(cur_app_node, NULL, chld_idx);
            if (strcmp("name", roxml_get_name(cur_chld_node, NULL, 0))==0) {
                node_t *text =  roxml_get_txt(cur_chld_node, 0);
                strcpy(app->name, roxml_get_content(text, NULL, 0, NULL));
            } else if (strcmp("description", roxml_get_name(cur_chld_node, NULL, 0))==0) {
                // do nothing, just iterate over it
            } else if (strcmp("servers", roxml_get_name(cur_chld_node, NULL, 0))==0){
                int idx2;
                app->num_servers = roxml_get_chld_nb(cur_chld_node);
                app->servers = (Server*)calloc(app->num_servers, sizeof(Server));
                for (idx2=0; idx2<roxml_get_chld_nb(cur_chld_node); idx2++) {
                    node_t *cur_idx2_node=roxml_get_chld(cur_chld_node, NULL, idx2);
                    int idx3;
                    for (idx3=0; idx3<roxml_get_chld_nb(cur_idx2_node); idx3++) {
                        node_t *cur_idx3_node=roxml_get_chld(cur_idx2_node, NULL, idx3);
                        if (strcmp("address", roxml_get_name(cur_idx3_node, NULL, 0))==0) {
                            node_t *text =  roxml_get_txt(cur_idx3_node, 0);
                            strcpy(app->servers[idx2].addr, roxml_get_content(text, NULL, 0, NULL));
                        } else if (strcmp("port", roxml_get_name(cur_idx3_node, NULL, 0))==0) {
                            node_t *text =  roxml_get_txt(cur_idx3_node, 0);
                            app->servers[idx2].port = atoi(roxml_get_content(text, NULL, 0, NULL));
                        }
                    }
                }
            } else if (strcmp("transport", roxml_get_name(cur_chld_node, NULL, 0))==0){
                int idx2;
                for (idx2=0; idx2<roxml_get_chld_nb(cur_chld_node); idx2++) {
                    node_t *cur_idx2_node=roxml_get_chld(cur_chld_node, NULL, idx2);
                    if (strcmp("ssh", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        app->transport_type = SSH;
                        node_t *hostkeys_node=roxml_get_chld(cur_idx2_node, NULL, 0);
                        assert(strcmp(roxml_get_name(hostkeys_node, NULL, 0), "host-keys")==0);
                        app->num_host_keys = roxml_get_chld_nb(hostkeys_node);
                        app->host_keys = (HostKey*)calloc(app->num_host_keys, sizeof(HostKey));
                        int idx3;
                        for (idx3=0; idx3 < app->num_host_keys; idx3++) {
                            node_t *cur_idx3_node=roxml_get_chld(hostkeys_node, NULL, idx3);
                            assert(strcmp(roxml_get_name(cur_idx3_node, NULL, 0), "host-key")==0);
                            node_t *name_node=roxml_get_chld(cur_idx3_node, NULL, 0);
                            assert(strcmp(roxml_get_name(name_node, NULL, 0), "name")==0);
                            node_t *text =  roxml_get_txt(name_node, 0);
                            strcpy(app->host_keys[idx3].name, 
                                   roxml_get_content(text, NULL, 0, NULL));
                        }
                    } else if (strcmp("tls", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        app->transport_type = TLS;
                    } else {
                        printf("Unrecognized transport type config file (%s) [2]\n",
                                                    roxml_get_name(cur_chld_node, NULL, 0));
                        roxml_release(RELEASE_ALL);
                        roxml_close(root);
                        return 1;
                   }
               }
            } else if (strcmp("connection-type", roxml_get_name(cur_chld_node, NULL, 0))==0){
                int idx2;
                for (idx2=0; idx2<roxml_get_chld_nb(cur_chld_node); idx2++) {
                    node_t *cur_idx2_node=roxml_get_chld(cur_chld_node, NULL, idx2);
                    if (strcmp("persistent", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        app->connection_type = PERSISTENT;
                        if (roxml_get_chld_nb(cur_idx2_node) != 0) {
                            node_t *keepalives_node=roxml_get_chld(cur_idx2_node, NULL, 0);
                            assert(strcmp(roxml_get_name(keepalives_node, NULL, 0), "keep-alives")==0);

                            int idx3;
                            for (idx3=0; idx3<roxml_get_chld_nb(keepalives_node); idx3++) {
                                node_t *cur_idx3_node=roxml_get_chld(keepalives_node, NULL, idx3);
                                if (strcmp("interval-secs", roxml_get_name(cur_idx3_node, NULL, 0))==0) {
                                    node_t *text = roxml_get_txt(cur_idx3_node, 0);
                                    app->keep_alive_strategy.interval_secs= atoi(roxml_get_content(text, NULL, 0, NULL));
                                } else if (strcmp("count-max", roxml_get_name(cur_idx3_node, NULL, 0))==0) {
                                    node_t *text = roxml_get_txt(cur_idx3_node, 0);
                                    app->keep_alive_strategy.count_max= atoi(roxml_get_content(text, NULL, 0, NULL));
                                } else {
                                    printf("Unrecognized keep-alives decendent element in config file (%s) [3]\n",
                                                         roxml_get_name(cur_idx3_node, NULL, 0));
                                    roxml_release(RELEASE_ALL);
                                    roxml_close(root);
                                    return 1;
                                }
                            }

                        }


/*
            } else if (strcmp("keep-alive-strategy", roxml_get_name(cur_chld_node, NULL, 0))==0){
                int idx2;
                for (idx2=0; idx2<roxml_get_chld_nb(cur_chld_node); idx2++) {
                    node_t *cur_idx2_node=roxml_get_chld(cur_chld_node, NULL, idx2);
                    if (strcmp("interval-secs", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        node_t *text =  roxml_get_txt(cur_idx2_node, 0);
                        app->keep_alive_strategy.interval_secs = atoi(roxml_get_content(text, NULL, 0, NULL));
                    } else if (strcmp("count-max", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        node_t *text =  roxml_get_txt(cur_idx2_node, 0);
                        app->keep_alive_strategy.count_max = atoi(roxml_get_content(text, NULL, 0, NULL));
                    }
                }
*/





                    } else if (strcmp("periodic", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        app->connection_type = PERIODIC;
                        int idx3;
                        for (idx3=0; idx3<roxml_get_chld_nb(cur_idx2_node); idx3++) {
                            node_t *cur_idx3_node=roxml_get_chld(cur_idx2_node, NULL, idx3);
                            if (strcmp("timeout-mins", roxml_get_name(cur_idx3_node, NULL, 0))==0) {
                                node_t *text =  roxml_get_txt(cur_idx3_node, 0);
                                app->periodic_connect_info.timeout_mins = atoi(roxml_get_content(text, NULL, 0, NULL));
                            } else if (strcmp("linger-secs", roxml_get_name(cur_idx3_node, NULL, 0))==0) {
                                node_t *text =  roxml_get_txt(cur_idx3_node, 0);
                                app->periodic_connect_info.linger_secs = atoi(roxml_get_content(text, NULL, 0, NULL));
                            }
                        }
                    }
                }
            } else if (strcmp("reconnect-strategy", roxml_get_name(cur_chld_node, NULL, 0))==0){
                int idx2;
                for (idx2=0; idx2<roxml_get_chld_nb(cur_chld_node); idx2++) {
                    node_t *cur_idx2_node=roxml_get_chld(cur_chld_node, NULL, idx2);
                    if (strcmp("start-with", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        node_t *text =  roxml_get_txt(cur_idx2_node, 0);
                        if (strcmp("first-listed", roxml_get_content(text, NULL, 0, NULL))==0) {
                            app->reconnect_strategy.start_with = FIRST_LISTED;
                        } else {
                            app->reconnect_strategy.start_with = LAST_CONNECTED;
                        }
                    } else if (strcmp("interval-secs", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        node_t *text =  roxml_get_txt(cur_idx2_node, 0);
                        app->reconnect_strategy.interval_secs = atoi(roxml_get_content(text, NULL, 0, NULL));
                    } else if (strcmp("count-max", roxml_get_name(cur_idx2_node, NULL, 0))==0) {
                        node_t *text =  roxml_get_txt(cur_idx2_node, 0);
                        app->reconnect_strategy.count_max = atoi(roxml_get_content(text, NULL, 0, NULL));
                    }
                }
            } else {
                printf("Unrecognized XML element in config file (%s) [1]\n",
                                                         roxml_get_name(cur_chld_node, NULL, 0));
                roxml_release(RELEASE_ALL);
                roxml_close(root);
                return 1;
            }
        }
    }
    roxml_release(RELEASE_ALL);
    roxml_close(root);

    return 0;
}



// This routine persists the state for the specified app.   Right now, 
// the persisted state is just the last server connected, which enables
// the "last connected" reconnection strategy to work across restarts.
int // 0=OK, 1=ERROR
set_persisted_state(const char* appname, PersistedState* state) {

  // This reference implementation simply reads the PersistedState
  // struct from a hidden file called ".<app-name>.state"

  FILE*  file;
  char   filename[32];
  size_t size;
  sprintf(filename, ".%s.state", appname);
  file = fopen(filename, "w");
  if (file == NULL) {
    return 1;
  }
  size = fwrite(state, sizeof(PersistedState), 1, file);
  if (size != 1) {
    printf("fwrite() failed\n");
    fclose(file);
    return 1;
  }
  fclose(file);
  return 0;
}






// This routine returns the persisted state for the specified app.
// Right now, the persisted state is just the last server connected,
// which enables the "last connected" reconnection strategy to work
// even across restarts.
int // 0=OK, 1=ERROR, 2=NOTFOUND
get_persisted_state(const char* appname, PersistedState* state) {

  // This reference implementation simply writes the PersistedState
  // struct to a hidden file called ".<app-name>.state"

  FILE*  file;
  char   filename[32];
  size_t size;
  sprintf(filename, ".%s.state", appname);
  file = fopen(filename, "r");
  if (file == NULL) {
    if (errno == ENOENT)
      return 2;
    return 1;
  }
  size = fread(state, sizeof(PersistedState), 1, file);
  if (size != 1) {
    printf("fread() failed\n");
    fclose(file);
    return 1;
  }
  fclose(file);
  return 0;
}



