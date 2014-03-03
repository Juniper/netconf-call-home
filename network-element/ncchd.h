/*****************************************************************************
Copyright (c) 2014, Juniper Networks, Inc.
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

   This header file defines some structs and externs that are used
   between the files ncchd.c and data_access_layer.c
 *****************************************************************************/


/*****************************************************************************
   STRUCTS
 *****************************************************************************/

typedef struct Server Server;
struct Server {
  char     addr[64]; // ip or domain name
  uint16_t port;
};

typedef struct HostKey HostKey;
struct HostKey {
  char name[64];
};

typedef struct PeriodicConnectInfo PeriodicConnectInfo;
struct PeriodicConnectInfo {
  uint8_t timeout_mins;
  uint8_t linger_secs;
};

enum START_WITH_ENUM { FIRST_LISTED, LAST_CONNECTED };
typedef struct ReconnectStrategy ReconnectStrategy;
struct ReconnectStrategy { 
  enum START_WITH_ENUM start_with;
  uint8_t              interval_secs;
  uint8_t              count_max;
};

typedef struct KeepAliveStrategy KeepAliveStrategy;
struct KeepAliveStrategy {
  uint8_t interval_secs;   // maps to ClientAliveInterval
  uint8_t count_max;       // maps to ClientAliveCountMax
};

enum TRANSPORT_TYPE { SSH, TLS };
enum CONNECT_TYPE { PERSISTENT, PERIODIC };
typedef struct Application Application;
struct Application {
  char                 name[64];              // unique across apps
  uint8_t              num_servers;
  Server              *servers;
  enum TRANSPORT_TYPE  transport_type;
  uint8_t              num_host_keys;         // set when transport_type==SSH
  HostKey             *host_keys;             // set when transport_type==SSH
  enum CONNECT_TYPE    connection_type;
  PeriodicConnectInfo  periodic_connect_info; // set when connection_type==PERIODIC
  ReconnectStrategy    reconnect_strategy;
  KeepAliveStrategy    keep_alive_strategy;

  // operational state (not config!)
  pid_t                connecting_pid;
};

typedef struct Configuration Configuration;
struct Configuration {
  Application   *apps;
  uint8_t        num_apps;
};

typedef struct PersistedState PersistedState;
struct PersistedState {
  Server last_connected;
};



/*****************************************************************************
   EXTERNS
 *****************************************************************************/

extern int get_incoming_config(Configuration* incoming_config);
extern int set_persisted_state(const char* appname, PersistedState* state);
extern int get_persisted_state(const char* appname, PersistedState* state);

