#################################################################################
#										#
#		Linux TPM 1.2 TSS and TPM 2.0 TSS and Utilities Makefile	#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile 1328 2018-09-04 15:08:15Z kgoldman $		#
#										#
# (c) Copyright IBM Corporation 2018						#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

# C compiler

CC = /usr/bin/gcc

# compile - common flags for TSS library and applications

CCFLAGS += 	-DTPM_POSIX

# example of pointing to a locally built openssl 1.1
# CCFLAGS += 	-I/home/kgold/openssl/include
CCFLAGS += -I/usr/local/ssl/include/

# compile - for TSS library

# include the hardening flag PIC needed for compiling for dynamic
# linking

CCLFLAGS += 	-I. 		\
		-fPIC		\
		-march=native	\
		-fcommon \
		-DTPM_TPM20	\
		-DTPM_TPM12

# to compile out printf's.  Regression test will fail because it tries
# to print a structure -DTPM_TSS_NO_PRINT

# example of changing the default interface type
#	-DTPM_INTERFACE_TYPE_DEFAULT="\"dev\""

# compile - for applications

# include the hardening flag PIE needed for compiling for
# static linking

CCAFLAGS += 	-I.		\
		-DTPM_TPM20	\
		-DTPM_TPM12	\
		-fPIC

# link - common flags flags TSS library and applications

LNFLAGS += 	-DTPM_POSIX		\
		-L.

# This seems to be required on some Ubuntu distros due to an issue with the gold linker
#		-fuse-ld=bfd

# example of pointing to a locally built openssl 1.1
# LNFLAGS +=	 -L/home/kgold/openssl
# This also requires setting the environment variable LD_LIBRARY_PATH.  E.g.,
# setenv LD_LIBRARY_PATH ${LD_LIBRARY_PATH}:/home/kgold/openssl
LNFLAGS +=       -L/usr/local/ssl/lib
# link - for TSS library

# hardening flags for linking shared objects
LNLFLAGS += -shared -Wl,-z,now

# This is an alternative to using the bfd linker on Ubuntu
LNLLIBS += -lcrypto

# link - for applications, TSS path, TSS and OpenSSl libraries

# hardening flags for linking executables
LNAFLAGS += -pie -Wl,-z,now -Wl,-rpath,.

LNALIBS +=  -libmtssutils -libmtss -lcrypto

# shared library

# versioned shared library
LIBTSSVERSIONED=libibmtss.so.1.1

# soname field of the shared library
# which will be made symbolic link to the versioned shared library
# this is used to provide version backward-compatibility information
LIBTSSSONAME=libibmtss.so.1

# symbolic link to the versioned shared library
# this allows linking to the shared library with '-libmtss'

os := $(shell uname -o)
ifeq ($(os),Cygwin)
  LIBTSS=libibmtss.dll
else
  LIBTSS=libibmtss.so
endif

# TSS utilities shared library

LIBTSSUTILSVERSIONED=libibmtssutils.so.1.1
LIBTSSUTILSSONAME=libibmtssutils.so.1
LIBTSSUTILS=libibmtssutils.so

# executable extension

EXE =

#


TSS_HEADERS=

# default TSS library

TSS_OBJS = 	tssfile.o 		\
		tsscryptoh.o 		\
		tsscrypto.o 		\
		tssprintcmd.o

TSSUTILS_OBJS = cryptoutils.o	\
		ekutils.o	\
		imalib.o	\
		eventlib.o

# common to all builds

include makefile-common
include makefile-common12
include makefile-common20

# default build target

all:	$(ALL)

# TSS shared library source

tss.o: 		$(TSS_HEADERS) tss.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tss.c
tssauth.o: 	$(TSS_HEADERS) tssauth.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssauth.c
tssproperties.o: $(TSS_HEADERS) tssproperties.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssproperties.c
tssmarshal.o: 	$(TSS_HEADERS) tssmarshal.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssmarshal.c
tsscryptoh.o: 	$(TSS_HEADERS) tsscryptoh.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsscryptoh.c
tsscrypto.o: 	$(TSS_HEADERS) tsscrypto.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsscrypto.c
tssutils.o: 	$(TSS_HEADERS) tssutils.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssutils.c
tssfile.o: 	$(TSS_HEADERS) tssfile.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssfile.c
tsssocket.o: 	$(TSS_HEADERS) tsssocket.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsssocket.c
tssdev.o: 	$(TSS_HEADERS) tssdev.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssdev.c
tsstransmit.o: 	$(TSS_HEADERS) tsstransmit.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsstransmit.c
tssresponsecode.o: $(TSS_HEADERS) tssresponsecode.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssresponsecode.c
tssccattributes.o: $(TSS_HEADERS) tssccattributes.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssccattributes.c
tssprint.o: 	$(TSS_HEADERS) tssprint.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssprint.c
tssprintcmd.o: 	$(TSS_HEADERS) tssprintcmd.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssprintcmd.c
Unmarshal.o: 	$(TSS_HEADERS) Unmarshal.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Unmarshal.c
Commands.o: 	$(TSS_HEADERS) Commands.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Commands.c
CommandAttributeData.o: 	$(TSS_HEADERS) CommandAttributeData.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) CommandAttributeData.c
ntc2lib.o:	$(TSS_HEADERS) ntc2lib.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) ntc2lib.c
tssntc.o:	$(TSS_HEADERS) tssntc.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssntc.c
fips202.o: $(TSS_HEADERS) fips202.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) fips202.c
kyber-cbd.o: $(TSS_HEADERS) kyber-cbd.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-cbd.c
kyber-indcpa.o: $(TSS_HEADERS) kyber-indcpa.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-indcpa.c
kyber-ntt.o: $(TSS_HEADERS) kyber-ntt.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-ntt.c
kyber-poly.o: $(TSS_HEADERS) kyber-poly.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-poly.c
kyber-polyvec.o: $(TSS_HEADERS) kyber-polyvec.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-polyvec.c
kyber-precomp.o: $(TSS_HEADERS) kyber-precomp.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-precomp.c
kyber-reduce.o: $(TSS_HEADERS) kyber-reduce.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-reduce.c
kyber-verify.o: $(TSS_HEADERS) kyber-verify.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) kyber-verify.c

# TPM 2.0

tss20.o: 	$(TSS_HEADERS) tss20.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tss20.c
tssauth20.o: 	$(TSS_HEADERS) tssauth20.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssauth20.c
# TPM 1.2

tss12.o: 	$(TSS_HEADERS) tss12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tss12.c
tssauth12.o: 	$(TSS_HEADERS) tssauth12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssauth12.c
tssmarshal12.o:	$(TSS_HEADERS) tssmarshal12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssmarshal12.c
Unmarshal12.o: 	$(TSS_HEADERS) Unmarshal12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Unmarshal12.c
Commands12.o: 	$(TSS_HEADERS) Commands12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Commands12.c
tssccattributes12.o: $(TSS_HEADERS) tssccattributes12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssccattributes12.c
CommandAttributeData12.o: 	$(TSS_HEADERS) CommandAttributeData12.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) CommandAttributeData12.c

# TSS utilities shared library source

cryptoutils.o: 	$(TSS_HEADERS) cryptoutils.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) cryptoutils.c
ekutils.o: 	$(TSS_HEADERS) ekutils.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) ekutils.c
imalib.o: 	$(TSS_HEADERS) imalib.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) imalib.c
eventlib.o: 	$(TSS_HEADERS) eventlib.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) eventlib.c

# TSS shared library build

$(LIBTSS): 	$(TSS_OBJS)
		$(CC) $(LNFLAGS) $(LNLFLAGS) -Wl,-soname,$(LIBTSSSONAME) -o $(LIBTSSVERSIONED) \
			$(TSS_OBJS) $(LNLLIBS)
		rm -f $(LIBTSSSONAME)
		ln -sf $(LIBTSSVERSIONED) $(LIBTSSSONAME)
		rm -f $(LIBTSS)
		ln -sf $(LIBTSSSONAME) $(LIBTSS)

# TSS utilities shared library

$(LIBTSSUTILS):	$(TSSUTILS_OBJS)
		$(CC) $(LNFLAGS) $(LNLFLAGS) -Wl,-soname,$(LIBTSSUTILSSONAME) -o $(LIBTSSUTILSVERSIONED) $(TSSUTILS_OBJS) $(LNLLIBS)
		rm -f $(LIBTSSSUTILSONAME)
		ln -sf $(LIBTSSUTILSVERSIONED) $(LIBTSSUTILSSONAME)
		rm -f $(LIBTSSUTILS)
		ln -sf $(LIBTSSUTILSSONAME) $(LIBTSSUTILS)

.PHONY:		clean
.PRECIOUS:	%.o

clean:
		rm -f *.o  *~ 		\
		h*.bin			\
		$(LIBTSSSONAME)		\
		$(LIBTSSVERSIONED) 	\
		$(LIBTSSUTILSSONAME) 	\
		$(LIBTSSUTILSVERSIONED)	\
		$(ALL)

# applications

activatecredential:	ibmtss/tss.h activatecredential.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) activatecredential.o $(LNALIBS) -o activatecredential
eventextend:		eventextend.o eventlib.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eventextend.o eventlib.o $(LNALIBS) -o eventextend
imaextend:		imaextend.o imalib.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) imaextend.o imalib.o $(LNALIBS) -o imaextend
certify:		ibmtss/tss.h certify.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) certify.o $(LNALIBS) -o certify
certifycreation:	ibmtss/tss.h certifycreation.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) certifycreation.o $(LNALIBS) -o certifycreation
changeeps:		ibmtss/tss.h changeeps.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) changeeps.o $(LNALIBS) -o changeeps
changepps:		ibmtss/tss.h changepps.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) changepps.o $(LNALIBS) -o changepps
clear:			ibmtss/tss.h clear.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clear.o $(LNALIBS) -o clear
clearcontrol:		ibmtss/tss.h clearcontrol.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clearcontrol.o $(LNALIBS) -o clearcontrol
clockrateadjust:	ibmtss/tss.h clockrateadjust.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clockrateadjust.o $(LNALIBS) -o clockrateadjust
clockset:		ibmtss/tss.h clockset.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) clockset.o $(LNALIBS) -o clockset
commit:			ibmtss/tss.h commit.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) commit.o $(LNALIBS) -o commit
contextload:		ibmtss/tss.h contextload.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) contextload.o $(LNALIBS) -o contextload
contextsave:		ibmtss/tss.h contextsave.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) contextsave.o $(LNALIBS) -o contextsave
create:			ibmtss/tss.h create.o objecttemplates.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) create.o objecttemplates.o $(LNALIBS) -o create
createloaded:		ibmtss/tss.h createloaded.o objecttemplates.o $(LIBTSS) $(LIBTTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createloaded.o objecttemplates.o $(LNALIBS) -o createloaded
createprimary:		ibmtss/tss.h createprimary.o objecttemplates.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createprimary.o objecttemplates.o $(LNALIBS) -o createprimary
dictionaryattacklockreset:		ibmtss/tss.h dictionaryattacklockreset.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) dictionaryattacklockreset.o $(LNALIBS) -o dictionaryattacklockreset
dictionaryattackparameters:		ibmtss/tss.h dictionaryattackparameters.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) dictionaryattackparameters.o $(LNALIBS) -o dictionaryattackparameters
duplicate:		ibmtss/tss.h duplicate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) duplicate.o $(LNALIBS) -o duplicate
eccparameters:		ibmtss/tss.h eccparameters.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eccparameters.o $(LNALIBS) -o eccparameters
ecephemeral:		ibmtss/tss.h ecephemeral.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ecephemeral.o $(LNALIBS) -o ecephemeral
encryptdecrypt:		ibmtss/tss.h encryptdecrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) encryptdecrypt.o $(LNALIBS) -o encryptdecrypt
eventsequencecomplete:	ibmtss/tss.h eventsequencecomplete.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) eventsequencecomplete.o $(LNALIBS) -o eventsequencecomplete
evictcontrol:		ibmtss/tss.h evictcontrol.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) evictcontrol.o $(LNALIBS) -o evictcontrol
flushcontext:		ibmtss/tss.h flushcontext.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) flushcontext.o $(LNALIBS) -o flushcontext
getcommandauditdigest:	ibmtss/tss.h getcommandauditdigest.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getcommandauditdigest.o $(LNALIBS) -o getcommandauditdigest
getcapability:		ibmtss/tss.h getcapability.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getcapability.o $(LNALIBS) -o getcapability
getrandom:		ibmtss/tss.h getrandom.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getrandom.o $(LNALIBS) -o getrandom
gettestresult:		ibmtss/tss.h gettestresult.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) gettestresult.o $(LNALIBS) -o gettestresult
getsessionauditdigest:	ibmtss/tss.h getsessionauditdigest.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) getsessionauditdigest.o $(LNALIBS) -o getsessionauditdigest
gettime:		ibmtss/tss.h gettime.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) gettime.o $(LNALIBS) -o gettime
hashsequencestart:	ibmtss/tss.h hashsequencestart.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hashsequencestart.o $(LNALIBS) -o hashsequencestart
hash:			ibmtss/tss.h hash.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hash.o $(LNALIBS) -o hash
hierarchycontrol:	ibmtss/tss.h hierarchycontrol.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hierarchycontrol.o $(LNALIBS) -o hierarchycontrol
hierarchychangeauth:	ibmtss/tss.h hierarchychangeauth.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hierarchychangeauth.o $(LNALIBS) -o hierarchychangeauth
hmac:			ibmtss/tss.h hmac.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hmac.o $(LNALIBS) -o hmac
hmacstart:		ibmtss/tss.h hmacstart.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) hmacstart.o $(LNALIBS) -o hmacstart
import:			ibmtss/tss.h import.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) import.o $(LNALIBS) -o import
importpem:		ibmtss/tss.h importpem.o objecttemplates.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) importpem.o objecttemplates.o $(LNALIBS) -o importpem
load:			ibmtss/tss.h load.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) load.o $(LNALIBS) -o load
loadexternal:		ibmtss/tss.h loadexternal.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) loadexternal.o $(LNALIBS) -o loadexternal
makecredential:		ibmtss/tss.h makecredential.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) makecredential.o $(LNALIBS) -o makecredential
nvcertify:		ibmtss/tss.h nvcertify.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvcertify.o $(LNALIBS) -o nvcertify
nvchangeauth:		ibmtss/tss.h nvchangeauth.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvchangeauth.o $(LNALIBS) -o nvchangeauth
nvdefinespace:		ibmtss/tss.h nvdefinespace.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvdefinespace.o $(LNALIBS) -o nvdefinespace
nvextend:		ibmtss/tss.h nvextend.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvextend.o $(LNALIBS) -o nvextend
nvglobalwritelock:	ibmtss/tss.h nvglobalwritelock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvglobalwritelock.o $(LNALIBS) -o nvglobalwritelock
nvincrement:		ibmtss/tss.h nvincrement.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvincrement.o $(LNALIBS) -o nvincrement
nvread:			ibmtss/tss.h nvread.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvread.o $(LNALIBS) -o nvread
nvreadlock:		ibmtss/tss.h nvreadlock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadlock.o $(LNALIBS) -o nvreadlock
nvreadpublic:		ibmtss/tss.h nvreadpublic.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvreadpublic.o $(LNALIBS) -o nvreadpublic
nvsetbits:		ibmtss/tss.h nvsetbits.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvsetbits.o $(LNALIBS) -o nvsetbits
nvundefinespace:	ibmtss/tss.h nvundefinespace.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvundefinespace.o $(LNALIBS) -o nvundefinespace
nvundefinespacespecial:	ibmtss/tss.h nvundefinespacespecial.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvundefinespacespecial.o $(LNALIBS) -o nvundefinespacespecial
nvwrite:		ibmtss/tss.h nvwrite.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwrite.o $(LNALIBS) -o nvwrite
nvwritelock:		ibmtss/tss.h nvwritelock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) nvwritelock.o $(LNALIBS) -o nvwritelock
objectchangeauth:	ibmtss/tss.h objectchangeauth.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) objectchangeauth.o $(LNALIBS) -o objectchangeauth
pcrallocate: 		ibmtss/tss.h pcrallocate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrallocate.o $(LNALIBS) -o pcrallocate
pcrevent: 		ibmtss/tss.h pcrevent.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrevent.o $(LNALIBS) -o pcrevent
pcrextend: 		ibmtss/tss.h pcrextend.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrextend.o $(LNALIBS) -o pcrextend
pcrread: 		ibmtss/tss.h pcrread.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrread.o $(LNALIBS) -o pcrread
pcrreset: 		ibmtss/tss.h pcrreset.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) pcrreset.o $(LNALIBS) -o pcrreset
policyauthorize:	ibmtss/tss.h policyauthorize.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyauthorize.o $(LNALIBS) -o policyauthorize
policyauthvalue:	ibmtss/tss.h policyauthvalue.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyauthvalue.o $(LNALIBS) -o policyauthvalue
policycommandcode:	ibmtss/tss.h policycommandcode.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policycommandcode.o $(LNALIBS) -o policycommandcode
policycphash:		ibmtss/tss.h policycphash.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policycphash.o $(LNALIBS) -o policycphash
policynamehash:		ibmtss/tss.h policynamehash.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policynamehash.o $(LNALIBS) -o policynamehash
policycountertimer:	ibmtss/tss.h policycountertimer.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policycountertimer.o $(LNALIBS) -o policycountertimer
policyduplicationselect:	ibmtss/tss.h policyduplicationselect.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyduplicationselect.o $(LNALIBS) -o policyduplicationselect
policygetdigest:	ibmtss/tss.h policygetdigest.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policygetdigest.o $(LNALIBS) -o policygetdigest
policymaker:		ibmtss/tss.h policymaker.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policymaker.o $(LNALIBS) -o policymaker
policymakerpcr:		ibmtss/tss.h policymakerpcr.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policymakerpcr.o $(LNALIBS) -o policymakerpcr
policyauthorizenv:	ibmtss/tss.h policyauthorizenv.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyauthorizenv.o $(LNALIBS) -o policyauthorizenv
policynv:		ibmtss/tss.h policynv.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policynv.o $(LNALIBS) -o policynv
policynvwritten:	ibmtss/tss.h policynvwritten.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policynvwritten.o $(LNALIBS) -o policynvwritten
policyor:		ibmtss/tss.h policyor.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyor.o $(LNALIBS) -o policyor
policypassword:		ibmtss/tss.h policypassword.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policypassword.o $(LNALIBS) -o policypassword
policypcr:		ibmtss/tss.h policypcr.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policypcr.o $(LNALIBS) -o policypcr
policyrestart:		ibmtss/tss.h policyrestart.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyrestart.o $(LNALIBS) -o policyrestart
policysigned:		ibmtss/tss.h policysigned.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policysigned.o $(LNALIBS) -o policysigned
policysecret:		ibmtss/tss.h policysecret.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policysecret.o $(LNALIBS) -o policysecret
policytemplate:		ibmtss/tss.h policytemplate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policytemplate.o $(LNALIBS) -o policytemplate
policyticket:		ibmtss/tss.h policyticket.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) policyticket.o $(LNALIBS) -o policyticket
quote:			ibmtss/tss.h quote.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) quote.o $(LNALIBS) -o quote
powerup:		ibmtss/tss.h powerup.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) powerup.o $(LNALIBS) -o powerup
readclock:		ibmtss/tss.h readclock.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) readclock.o $(LNALIBS) -o readclock
readpublic:		ibmtss/tss.h readpublic.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) readpublic.o $(LNALIBS) -o readpublic
returncode:		ibmtss/tss.h returncode.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) returncode.o $(LNALIBS) -o returncode
rewrap:			ibmtss/tss.h rewrap.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) rewrap.o $(LNALIBS) -o rewrap
rsadecrypt: 		ibmtss/tss.h rsadecrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) rsadecrypt.o $(LNALIBS) -o rsadecrypt
rsaencrypt: 		ibmtss/tss.h rsaencrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) rsaencrypt.o $(LNALIBS) -o rsaencrypt
sequenceupdate:		ibmtss/tss.h sequenceupdate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sequenceupdate.o $(LNALIBS) -o sequenceupdate
sequencecomplete:	ibmtss/tss.h sequencecomplete.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sequencecomplete.o $(LNALIBS) -o sequencecomplete
setprimarypolicy:	ibmtss/tss.h setprimarypolicy.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) setprimarypolicy.o $(LNALIBS) -o setprimarypolicy
shutdown:		ibmtss/tss.h shutdown.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) shutdown.o $(LNALIBS) -o shutdown
sign:			ibmtss/tss.h sign.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) sign.o $(LNALIBS) -o sign
startauthsession:	ibmtss/tss.h startauthsession.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) startauthsession.o $(LNALIBS) -o startauthsession
startup:		ibmtss/tss.h startup.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) startup.o $(LNALIBS) -o startup
stirrandom:		ibmtss/tss.h stirrandom.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) stirrandom.o $(LNALIBS) -o stirrandom
unseal:			ibmtss/tss.h unseal.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) unseal.o $(LNALIBS) -o unseal
verifysignature:	ibmtss/tss.h verifysignature.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) verifysignature.o $(LNALIBS) -o verifysignature
zgen2phase:		ibmtss/tss.h zgen2phase.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) zgen2phase.o $(LNALIBS) -o zgen2phase
signapp:		ibmtss/tss.h signapp.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) signapp.o $(LNALIBS) -o signapp
writeapp:		ibmtss/tss.h writeapp.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) writeapp.o $(LNALIBS) -o writeapp
timepacket:		ibmtss/tss.h timepacket.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) timepacket.o $(LNALIBS) -o timepacket
createek:		createek.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createek.o $(LNALIBS) -o createek
createekcert:		createekcert.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) createekcert.o $(LNALIBS) -o createekcert
tpm2pem:		tpm2pem.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) tpm2pem.o $(LNALIBS) -o tpm2pem
tpmpublic2eccpoint:	tpmpublic2eccpoint.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) tpmpublic2eccpoint.o $(LNALIBS) -o tpmpublic2eccpoint
ntc2getconfig:		ntc2getconfig.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ntc2getconfig.o $(LNALIBS) -o ntc2getconfig
ntc2preconfig:		ntc2preconfig.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ntc2preconfig.o $(LNALIBS) -o ntc2preconfig
ntc2lockconfig:		ntc2lockconfig.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) ntc2lockconfig.o $(LNALIBS) -o ntc2lockconfig
kyberdecrypt:		ibmtss/tss.h kyberdecrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) kyberdecrypt.o $(LNALIBS) -o kyberdecrypt
kyberencrypt:		ibmtss/tss.h kyberencrypt.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) kyberencrypt.o $(LNALIBS) -o kyberencrypt
encapsulate:		ibmtss/tss.h encapsulate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) encapsulate.o $(LNALIBS) -o encapsulate
decapsulate:		ibmtss/tss.h decapsulate.o $(LIBTSS) $(LIBTSSUTILS)
			$(CC) $(LNFLAGS) $(LNAFLAGS) decapsulate.o $(LNALIBS) -o decapsulate

# for applications, not for TSS library

%.o:		%.c ibmtss/tss.h
		$(CC) $(CCFLAGS) $(CCAFLAGS) $< -o $@

