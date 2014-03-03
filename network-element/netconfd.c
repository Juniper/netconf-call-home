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

   This is the "netconf" subsystem that SSHD will start when requested.
   It only knows how to send its <hello> message and process a few 
   message from the NETCONF client (<set-public-key> & <close-session>) 
 *****************************************************************************/


/*****************************************************************************
   INCLUDES
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*****************************************************************************
   GLOBAL VARIABLES
 *****************************************************************************/

static char server_hello[] = "\
<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n\
  <capabilities>\n\
    <capability>urn:ietf:params:netconf:base:1.1</capability>\n\
  </capabilities>\n\
  <session-id>1</session-id>\n\
</hello>\n\
]]>]]>\n\
";

static char server_close_reply[] = "\
<rpc-reply message-id=\"%d\"\n\
           xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n\
  <ok/>\n\
</rpc-reply>\n\
]]>]]>\n\
";


/*****************************************************************************
   MAIN
 *****************************************************************************/

int  // currently always returns 0
main(int argc, char* argv[]) {
    char buf[2048];
    int  close_session = 0;
    int  read_public_key = 0;
    int  message_id = 101;  // should read messege-id from client

    printf("%s", server_hello);
    fflush(NULL);

    while (fgets (buf, sizeof(buf), stdin) != NULL) {

        if (read_public_key == 1) {
            // save it to the ~/.ssh/authorized_keys file
            char path[512];
            sprintf(path, "%s/.ssh/authorized_keys", getenv("HOME"));
            FILE *file = fopen(path, "a");
            fprintf(file, "%s", buf); 
            fclose(file);
            read_public_key = 0;
        }

        if (strstr(buf, "<set-public-key") != NULL) {
            read_public_key = 1;
        }

        if (strstr(buf, "close-session") != NULL) {
            close_session = 1;
        }

        if (strstr(buf, "]]>]]>") != NULL) {

            if (close_session == 1) {
                printf(server_close_reply, message_id); 
                fflush(NULL);
                exit(0);
            }


        }
    }
    exit(0);
}


