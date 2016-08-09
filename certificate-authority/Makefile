# Copyright (c) 2014-2016, Juniper Networks, Inc.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright 
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its 
#    contributors may be used to endorse or promote products derived 
#    from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.



OPENSSL = openssl
#OPENSSL = /usr/local/openssl-1.0.2g/bin/openssl 


all: public/trusted_ca_cert.pem


private:
	@mkdir private
	@chmod 700 private


private/key.pem: private
	$(OPENSSL) ecparam -out private/key.pem -genkey -name prime256v1



public:
	@mkdir public


public/trusted_ca_cert.pem: public private/key.pem
	$(OPENSSL) req -x509 -new -key private/key.pem -config conf/openssl.cnf -days 3650 -out public/trusted_ca_cert.pem


signed-keys:
	@mkdir signed-keys

conf/serial:
	@echo "01" > conf/serial

conf/index:
	@touch conf/index

sign_request: signed-keys conf/serial conf/index public/trusted_ca_cert.pem
	@read -p "filename of cert request file:" filename; \
	if [ -e $$filename ]; then \
	    outpath=`echo $$filename | sed 's/cert_request/signed_cert/'`; \
	    $(OPENSSL) ca -batch -config conf/openssl.cnf -in $$filename -out $$outpath -notext; \
	    echo "saved $$outpath"; \
	else \
	    echo; echo "error: $$filename not found"; echo; \
	fi


clean:
	@rm -rf private public signed-keys
	@rm -f conf/serial*
	@rm -f conf/index*

