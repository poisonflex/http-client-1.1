#define _WIN32_WINNT 0x0601
//this file contain workable flag/s ( -o, -X, -d, --port, --plain, --debug, -h )

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <zlib.h>
#include <brotli/decode.h>
#include <time.h>


//#define PORT "443"
#define MAX_COOKIES 32
#define MAX_COOKIE_LEN 256
#define MAX_DOMAIN_LEN 128
#define MAX_PATH_LEN   128

#define COOKIE_FILE "cookies.bin"

struct Cookie {
      char name[MAX_COOKIE_LEN];
      char value[MAX_COOKIE_LEN];
      char domain[MAX_DOMAIN_LEN];
      char path[MAX_PATH_LEN];
      int  secure; // 1 = only send over tls
      long expires; // Unix time; 0 = session cookie (no expiry)

};


// Presist cookie store: [int count][struct Cookie × count].Returns number of cookies loaded of cookies loaded (0 if file missing)

int cookies_load(struct Cookie *store, int max, const char *path) {
      FILE *f = fopen(path, "rb");
      if (f == NULL) return 0;
      int n = 0;
      if (fread(&n, sizeof(int), 1, f) != 1 || n < 0 || n > max) { fclose(f); return 0; }
      if (fread(store, sizeof(struct Cookie), (size_t)n, f) != (size_t)n) n = 0;
      fclose(f);
      return n;
}

int cookies_save(const struct Cookie *store, int n, const char *path) {
      FILE *f = fopen(path, "wb");
      if (f == NULL) return -1;
      fwrite(&n, sizeof(int), 1, f);
      fwrite(store, sizeof(struct Cookie), (size_t)n, f);
      fclose(f);
      return 0;

}



// * Body start : single slnk for body bytes.
// * - use_gzip == 0 -> straight fwrite to file (original behaviour)
// * - use_gzip == 1 -> feed z_stream, drain inflated output to file
// * Return bytes accepted, or -i on inflated error
// * RFC 3986 §5.2.4 - remove_dor_segments
// * Resolves "." and ".." segments in an absolute path
// * Preserving trailing-slash semantics (/a/b/.. -> /a/, not /a)

void normalize_path(const char *in, char *out, size_t outsz) {
      size_t starts[64];
      int    nseg = 0;
      size_t o    = 0;
      const char *p = in;
      int wants_trailing = 0;

      if (*p != '/') { // not absolute, pass teough
          snprintf(out, outsz, "%s", in);
          return;
      }
      out[o++] = '/';
      p++;

      while (*p) {
          const char *seg_start = p;
          while (*p && *p != '/') p++;
          size_t seg_len = (size_t)(p - seg_start);

          wants_trailing = (*p == '/');
          if (*p == '/') p++;

          if (seg_len == 0) continue; // "//"
          if (seg_len == 1 && seg_start[0] == '.') { // "."
              wants_trailing = 1;
              continue;
          }
          if (seg_len == 2 && seg_start[0] == '.' && seg_start[1] == '.') {
              if (nseg > 0) o = starts[--nseg];  // ".."
              wants_trailing = 1;
              continue;
          }
          if (nseg < 64) starts[nseg++] = o;
          if (o + seg_len + 1 >= outsz) break;
          memcpy(out + o, seg_start, seg_len);
          o += seg_len;
          out[o++] = '/';
      }
   
      if (!wants_trailing && o > 1 && out[o - 1] == '/') o--;
      out[o] = '\0';
}

int body_write(FILE *out, z_stream *zs, int use_gzip, BrotliDecoderState *br, int use_brotli, const unsigned char *buf, int len) {
      if (!use_gzip && !use_brotli) {
          fwrite(buf, 1, len, out);
          return len;
      }

      unsigned char outbuf[8192];

      if (use_gzip) {
          zs->next_in  = (Bytef *)buf;
          zs->avail_in = (uInt)len;
          while (zs->avail_in > 0) {
                zs->next_out  = outbuf;
                zs->avail_out = (uInt)sizeof(outbuf);
                int r = inflate(zs, Z_NO_FLUSH);
                if (r != Z_OK && r != Z_STREAM_END) {
                    printf("inflate error: %d\n", r);
                    return -1;
                }
                int produced = (int)sizeof(outbuf) - (int)zs->avail_out;
                if (produced > 0) fwrite(outbuf, 1, produced, out);
                if (r == Z_STREAM_END) break ;
          }
          return len;
      }
      

      // brotli 
      const uint8_t *in  = buf;
      size_t         inlen = (size_t)len;
      while (inlen > 0) {
          uint8_t *outp = outbuf;
          size_t   outlen = sizeof(outbuf);
          BrotliDecoderResult r = BrotliDecoderDecompressStream(br, &inlen, &in, &outlen, &outp, NULL);
          int produced = (int)sizeof(outbuf) - (int)outlen;
          if (produced > 0) fwrite(outbuf, 1, produced, out);
          if (r == BROTLI_DECODER_RESULT_ERROR) {
             printf("brotli decode error\n");
             return -1;
          }
          if (r == BROTLI_DECODER_RESULT_SUCCESS) break;
          // NEEDS_MORE_INPUT with inlen still > 0 shoultn't happened, but guard anyway
          if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && inlen == 0) break;
      }

      return len;
}




int main(int argc, char *argv[])
{
      setvbuf(stdout, NULL, _IONBF, 0);
      if (argc < 3) {
          printf("Usage: %s <host> <path> [body] [port]\n", argv[0]);
          return 1;
      }
      char current_host[256];
      char current_path[512];
      strncpy(current_host, argv[1], sizeof(current_host) - 1);
      current_host[sizeof(current_host) - 1] = '\0';
      strncpy(current_path, argv[2], sizeof(current_path) - 1);
      current_path[sizeof(current_path) -1] = '\0';

      WSADATA wsaData;
      int result = WSAStartup(MAKEWORD(2, 2), &wsaData);


      SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
      if (ctx == NULL) {
          ERR_print_errors_fp(stderr);
          WSACleanup();
          return 1;
      }
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
      // Try several standard location in order. First one that loads wins
      const char *env_cert = getenv("SSL_CERT_FILE");
      const char *ca_candidates[] = {
            env_cert != NULL ? env_cert : "",      // user override or skip
            "ca-bundle.crt",             // next to exe
            "C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt",
            "C:/msys64/mingw64/ssl/certs/ca-bundle.crt",
            "C:/Program Files/Git/mingw64/etc/ssl/certs/ca-bundle.crt",
            "C:/Program Files/Git/mingw64/ssl/certs/ca-bundle.crt",
            NULL
      };
      int ca_loaded = 0;
      for (int i = 0; ca_candidates[i] != NULL; i++) {
            if (ca_candidates[i][0] == '\0') continue;
            if (SSL_CTX_load_verify_locations(ctx, ca_candidates[i], NULL) == 1) {
                printf("Using CA bundle: %s\n", ca_candidates[i]);
                ca_loaded = 1;
                break;
            }
      }
      if (!ca_loaded) {
            fprintf(stderr, "fatal: no CA bundle found. Set SSL_CERT_FILE env var.\n");
            SSL_CTX_free(ctx);
            WSACleanup();
            return 1;
      }

      struct addrinfo hints;
      struct addrinfo *res = NULL;
      struct addrinfo *p = NULL;

      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_INET;  // IPv4 for simplicity now
      hints.ai_socktype = SOCK_STREAM;  //TCP
      hints.ai_protocol = IPPROTO_TCP;
      

      const char *method = "GET";
      const char *body   = "";
      size_t body_len    = 0;
      const char *port_arg = NULL;
      
      const char *out_path  = "decoded_body.html";
      int         use_plain = 0;
      int         debug_on  = 0;
      // flag/s
      for (int i = 3; i < argc; i++) {
          if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
              out_path = argv[++i];
          } else if (strcmp(argv[i], "-X") == 0 && i + 1 < argc) {
              method = argv[++i];
          } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
              body     = argv[++i];
              body_len = strlen(body);
          } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
              port_arg = argv[++i];
          } else if (strcmp(argv[i], "--plain") == 0) {
              use_plain = 1;
          } else if (strcmp(argv[i], "--debug") == 0) {
              debug_on = 1;
          } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
              printf("Usage: %s <host> <path> [flags]\n", argv[0]);
              printf("  -o <file>       Output file. \"-\" = stdout. default: decoded_body.html\n");
              printf("  -X <method>     HTTP method. Default: GET, or POST if -d given.\n");
              printf("  -d <body>       Request body. Implies POST unless -X overrides.\n");
              printf("  --port <n>      Port. Default: 443 (TLS), or 80 if --plain.\n");
              printf("  --plain         Plain TCP, no TLS.\n");
              printf("  --debug         Print request bytes to stderr.\n");
              return 0;
          } else {
              fprintf(stderr, "unknown arg (try -h or --help): %s\n", argv[i]);
              return 1;
          }
      }
      // -d implies POST, unless the user explicity set -X
      int method_explicit = 0;
      for (int i = 3; i < argc; i++) {
           if (strcmp(argv[i], "-X") == 0) { method_explicit = 1; break; }
      }
      if (!method_explicit && body_len > 0) method = "POST";
      
//      printf("DBG parse: out=%s method=%s body=%s port=%s plain=%d debug=%d\n", out_path, method, body, port_arg ? port_arg : "(null)", use_plain, debug_on);



      char current_port[8];
      int use_tls = 1;
      if (port_arg != NULL) {
          strncpy(current_port, port_arg, sizeof(current_port) - 1);
          current_port[sizeof(current_port) - 1] = '\0';
      } else if (use_plain) {
          strcpy(current_port, "80");
      } else {
          strcpy(current_port, "443");
      }
      if (use_plain) use_tls = 0;


      struct Cookie cookies[MAX_COOKIES];
      int cookie_count = cookies_load(cookies, MAX_COOKIES, COOKIE_FILE);
      if (cookie_count > 0) {
          printf("Loaded %d cookies from %s\n", cookie_count, COOKIE_FILE);
      }
      // declare connection state before the hop loop
      SOCKET sock = INVALID_SOCKET;
      SSL  *ssl = NULL;
      char conn_host[256] = {0};
      char conn_port[8]   = {0};
      int  conn_tls       = -1;

      for (int hop = 0; hop < 5; hop++) {
          int server_said_close = 0;
          int reuse_ok = (sock != INVALID_SOCKET) && (strcmp(conn_host, current_host) == 0) && (strcmp(conn_port, current_port) == 0) && (conn_tls == use_tls);
          if (!reuse_ok) {
          result = getaddrinfo(current_host, current_port, &hints, &res);
          if (result != 0) {
              printf("getaddrinfo failed: %d\n", result);
              WSACleanup();
              return 1;
          }


          sock = INVALID_SOCKET;

          for (p = res; p != NULL; p = p->ai_next) {
              sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
              if (sock == INVALID_SOCKET) {
                  continue;
              }

          if (connect(sock, p->ai_addr, (int)p->ai_addrlen) != SOCKET_ERROR) {
              DWORD rcv_to = 15000;  // 15 s: generous for slow servers, finite for close-delimited hangs
              setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rcv_to, sizeof(rcv_to));
              break;
          }



          closesocket(sock);
          sock = INVALID_SOCKET;
      }



      freeaddrinfo(res);


      if (sock == INVALID_SOCKET) {
          printf("Unable to connect to %s\n", current_host);
          SSL_CTX_free(ctx);
          WSACleanup();
          return 1;
      }
          strncpy(conn_host, current_host, sizeof(conn_host) - 1);
          conn_host[sizeof(conn_host) - 1] = '\0';
          strncpy(conn_port, current_port, sizeof(conn_port) - 1);
          conn_port[sizeof(conn_port) - 1] = '\0';
          conn_tls = use_tls;
          }  // end if (!reuse_ok)
 
      if (!reuse_ok && use_tls) {
          ssl = SSL_new(ctx);
          if (ssl == NULL) {
              ERR_print_errors_fp(stderr);
              closesocket(sock);
              SSL_CTX_free(ctx);
              WSACleanup();
              return 1;
          }
          SSL_set_fd(ssl, (int)sock);
          SSL_set_tlsext_host_name(ssl, current_host);  /* SNI */
          if (SSL_connect(ssl) != 1) {
              printf("TLS handshake failed\n");
              ERR_print_errors_fp(stderr);
              SSL_free(ssl);
              closesocket(sock);
              SSL_CTX_free(ctx);
              WSACleanup();
              return 1;
          }
          long vr = SSL_get_verify_result(ssl);
          if (vr != X509_V_OK) {
              printf("certificate verification failed: %s\n", X509_verify_cert_error_string(vr));
              SSL_free(ssl);
              closesocket(sock);
              SSL_CTX_free(ctx);
              WSACleanup();
              return 1;
          }

          X509 *peer = SSL_get_peer_certificate(ssl);
          if (peer != NULL) {
              char *subj = X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
              printf("TLS %s, cipher %s, cert CN=%s\n", SSL_get_version(ssl), SSL_get_cipher(ssl), subj != NULL ? subj : "?");
              if (subj) OPENSSL_free(subj);
              X509_free(peer);
          } else {
              printf("TLS %s, cipher %s, (no peer cert)\n", SSL_get_version(ssl), SSL_get_cipher(ssl));
          }


      }
       
      char cookie_header[2048] = {0};
      int cookie_header_len = 0;
      int cookies_sent = 0;
      for (int i = 0; i < cookie_count; i++) {
          // domain match: exact, or host ends with "." + domain
          const char *cd = cookies[i].domain;
          size_t hlen = strlen(current_host);
          size_t dlen = strlen(cd);
          int match = 0;
          if (dlen > 0 && hlen >= dlen) {
              if (_stricmp(current_host + (hlen - dlen), cd) == 0) {
                  // exact, or preceding char is '.' (covers leading dot too)
                  if (hlen == dlen || current_host[hlen - dlen - 1] == '.' || cd[0] == '.') {
                      match = 1;
                  }
              }
          }
             // skip secure cookies over plain http 
          if (!match) continue;
          if (cookies[i].secure && !use_tls) continue;
          int need = (int)(strlen(cookies[i].name) + strlen(cookies[i].value) + 4);

          if (cookie_header_len + need >= (int)sizeof(cookie_header)) break;

          if (cookies_sent == 0) {
              strcpy(cookie_header, "Cookie: ");
              cookie_header_len = 8;
          } else {
              strcpy(cookie_header + cookie_header_len, "; ");
              cookie_header_len += 2;
          }
          strcpy(cookie_header + cookie_header_len, cookies[i].name);
          cookie_header_len += (int)strlen(cookies[i].name);
          cookie_header[cookie_header_len++] = '=';
          strcpy(cookie_header + cookie_header_len, cookies[i].value);
          cookie_header_len += (int)strlen(cookies[i].value);
          cookies_sent++;
      }
      if (cookies_sent > 0) {
          strcpy(cookie_header + cookie_header_len, "\r\n");
      }
      // Purge expired cookies (expires > 0 means "has an expiry", 1 means "already dead")
      long now = (long)time(NULL);
      int live = 0;
      for (int i = 0; i < cookie_count; i++) {
          if (cookies[i].expires != 0 && cookies[i].expires <= now) continue;
          if (live != i) cookies[live] = cookies[i];
          live++;
      }
      cookie_count = live;

      char request[4096];
      char host_header[300];
      if (strcmp(current_port, "443") == 0 || strcmp(current_port, "80") == 0) {
          snprintf(host_header, sizeof(host_header), "%s", current_host);
      } else {
          snprintf(host_header, sizeof(host_header), "%s:%s", current_host, current_port);
      }
      char cl_header[64] = {0};
      if (body_len > 0) {
          snprintf(cl_header, sizeof(cl_header), "Content-Length: %zu\r\n", body_len);
      }
      snprintf(request, sizeof(request),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: BigFish/0.1\r\n"
        "Accept-Encoding: gzip, br\r\n"
        "%s"
        "%s"
        "Connection: keep-alive\r\n" 
        "\r\n"
        "%s",
        method, current_path, host_header, cookie_header, cl_header, body);

      if (debug_on) {
          fprintf(stderr, "--- REQUEST ---\n");
          fwrite(request, 1, strlen(request), stderr);
          fprintf(stderr, "--- END REQUEST ---\n");
      }
      int sent = use_tls
          ? SSL_write(ssl, request, (int)strlen(request))
          : send(sock, request, (int)strlen(request), 0);
      if (sent <= 0) {
          printf("SSL_write failed\n");
          ERR_print_errors_fp(stderr);
          if (ssl) SSL_free(ssl);
          closesocket(sock);
          SSL_CTX_free(ctx);
          WSACleanup();
          return 1;
      }

      printf("Sent %d bytes\n\n", sent);


      char buffer[4096];
      char raw[65536];
      int got = 0;
      int scanned = 0;
      int header_end = -1;

      /* Phase 1: read until headers are complete (\r\n\r\n) */
      while (header_end == -1) {
           int bytes = use_tls ? SSL_read(ssl, buffer, sizeof(buffer) - 1) : recv(sock, buffer, sizeof(buffer) - 1, 0);
           if (bytes <= 0) break;
           if (got + bytes > (int)sizeof(raw)) {
               printf("Headers too large for buffer\n");
               break;
           }
           memcpy(raw + got, buffer, bytes);
           got += bytes;

           // only scan from where the last scan stopped, minus 3 bytes so a \r\n\r\n stradding two reads is still detected
           int start = (scanned > 3) ? scanned - 3 : 0;
           for (int i = start; i + 3 < got; i++) {
               if (raw[i]     == 0x0D && raw[i + 1] == 0x0A &&
                   raw[i + 2] == 0x0D && raw[i + 3] == 0x0A) {
                   header_end = i;
                   break;
               }
           }
           if (header_end == -1) scanned = got;
      }

      



      if (header_end == -1) {
          printf("Could not find end of headers\n");
          closesocket(sock);
          WSACleanup();
          return 1;
      }
  ///// the loop does things

      char *line_start = raw;
      char *line_end;
      int content_length = -1;
      char location[512] = {0};
      int status_code = -1;
      int is_chunked = 0;
      char content_encoding[64] = {0};
      while (line_start < raw + header_end) { 
            line_end = memchr(line_start, '\n', (raw + header_end + 2) - line_start);
            if (line_end == NULL) break;
            size_t len = (size_t)(line_end - line_start);
            if (len > 0 && line_start[len - 1] == '\r') len--;
            if (len > 15 && _strnicmp(line_start, "Content-Length:", 15) == 0) {
                const char *v = line_start + 15;
                while (*v == ' ' || *v == '\t') v++;
                content_length = atoi(v);  // here
            }
            if (len > 18 && _strnicmp(line_start, "Transfer-Encoding:", 18) == 0) {
                const char *v = line_start + 18;
                while (*v == ' ' || *v == '\t') v++;
                if (len >= (size_t)(v - line_start) + 7 &&
                _strnicmp(v, "chunked", 7) == 0) {
                  is_chunked = 1;
                }
            }
            if (len > 17 && _strnicmp(line_start, "Content-Encoding:", 17) == 0) {
                const char *v = line_start + 17;
                while (*v == ' ' || *v == '\t') v++;
                size_t vlen = len - (size_t)(v - line_start);
                if (vlen >= sizeof(content_encoding)) vlen = sizeof(content_encoding) - 1;
                memcpy(content_encoding, v, vlen);
                content_encoding[vlen] = '\0';
            }
            if (len > 11 && _strnicmp(line_start, "Connection:", 11) == 0) {
                const char *v = line_start + 11;
                while (*v == ' ' || *v == '\t') v++;
                if (len >= (size_t)(v - line_start) + 5 && _strnicmp(v, "close", 5) == 0) {
                     server_said_close = 1;
                }
            }
            if (len > 11 && _strnicmp(line_start, "Set-Cookie:", 11) == 0) {
                const char *v = line_start + 11;
                while (*v == ' ' || *v == '\t') v++;
                size_t avail = len - (size_t)(v - line_start);
                //  name=value up to first ';' 
                const char *semi = memchr(v, ';', avail);
                size_t nv_len = (semi != NULL) ? (size_t)(semi - v) : avail;

                if (nv_len > 0 && nv_len < MAX_COOKIE_LEN && cookie_count < MAX_COOKIES) {
                     // find 'name=' prefix to test against existing cookies
                     const char *eqp = memchr(v, '=', nv_len);
                     size_t name_len = (eqp != NULL) ? (size_t)(eqp - v) : nv_len;

                     // existing same-name cookie (any-domain) -> overwrite in place
                     int slot = cookie_count;
                     for (int k = 0; k < cookie_count; k++) {
                         if (strlen(cookies[k].name) == name_len && memcmp(cookies[k].name, v, name_len) == 0) {
                             slot = k;
                             break;
                         }
                     }

                     struct Cookie *c = &cookies[slot];
                     memset(c, 0, sizeof(*c));
                     // split on '*'
                     const char *eq = memchr(v, '=', nv_len);
                     if (eq != NULL) {
                         size_t nlen = (size_t)(eq - v);
                         size_t vlen = nv_len - nlen - 1;
                         if (nlen < MAX_COOKIE_LEN && vlen < MAX_COOKIE_LEN) {
                             memcpy(c->name, v, nlen); c->name[nlen] = '\0';
                             memcpy(c->value, eq + 1, vlen); c->value[vlen] = '\0';

                             // default domain = current host; default path = "/"
                             strncpy(c->domain, current_host, MAX_DOMAIN_LEN - 1);
                             strcpy(c->path, "/");

                             // scan attributes for Domain= and Path=
                             const char *p = (semi != NULL) ? semi + 1 : NULL;
                             const char *end = v + avail;
                             while (p != NULL && p < end) {
                                   while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) p++;
                                   const char *aend = p;
                                   while (aend < end && *aend != ';') aend++;
                               
                                   if (_strnicmp(p, "Domain=", 7) == 0 && aend - p > 7) {
                                       size_t dlen = (size_t)(aend - p - 7);
                                       if (dlen >= MAX_DOMAIN_LEN) dlen = MAX_DOMAIN_LEN - 1;
                                       memcpy(c->domain, p + 7, dlen);
                                       c->domain[dlen] = '\0';
                                   } else if (_strnicmp(p, "Path=", 5) == 0 && aend - p > 5) {
                                       size_t plen = (size_t)(aend - p - 5);
                                       if (plen >= MAX_PATH_LEN) plen = MAX_PATH_LEN - 1;
                                       memcpy(c->path, p + 5, plen);
                                       c->path[plen] = '\0'; //
                                   } else if (aend - p == 6 && _strnicmp(p, "Secure", 6) == 0) {
                                          c->secure = 1;
                                   } else if (_strnicmp(p, "Max-Age=", 8) == 0 && aend - p > 8) {
                                          long secs = atol(p + 8);
                                          c->expires = (secs <= 0) ? 1 : (long)time(NULL) + secs;
                                   } else if (_strnicmp(p, "Expires=", 8) == 0 && aend - p > 8) {
                                          char tmp[64];
                                          size_t tlen = (size_t)(aend - p - 8);
                                          if (tlen >= sizeof(tmp)) tlen = sizeof(tmp) - 1;
                                          memcpy(tmp, p + 8, tlen);
                                          tmp[tlen] = '\0';
                                          // ACCept both: "wed, 28 oct 2026 12:00:00 gmt" and "Wed, 27-Oct-2027 11:15:12 gmt" (Google)
                                          char mon[4] = {0};
                                          int day = 0, year = 0, hh = 0, mm = 0, ss = 0;
                                          int ok = sscanf(tmp, "%*3s, %d %3s %d %d:%d:%d", &day, mon, &year, &hh, &mm, &ss);
                                          if (ok != 6) {
                                              ok = sscanf(tmp, "%*3s, %d-%3s-%d %d:%d:%d", &day, mon, &year, &hh, &mm, &ss);
                                          }
                                          if (ok == 6) {
                                              static const char *months[] = { "Jan","Feb","Mar","Apr","May","Jun","Jul","Agu","Sep","Oct","Nov","Dec" };
                                              int m = -1;
                                              for (int k = 0; k < 12; k++) {
                                                   if (_stricmp(mon, months[k]) == 0) {m = k; break; }
                                              }
                                              if (m >= 0) {
                                                   struct tm tm = {0};
                                                   tm.tm_year = year - 1900;
                                                   tm.tm_mon  = m;
                                                   tm.tm_mday = day;
                                                   tm.tm_hour = hh;
                                                   tm.tm_min  = mm;
                                                   tm.tm_sec  = ss;
                                                   c->expires = (long)_mkgmtime(&tm);
                                              }
                                          }
                                   }
                                   p = (aend < end) ? aend + 1 : NULL;
                             }
                             if (slot == cookie_count) cookie_count++;
                         }
                     }
                }
            }

            if (len > 9 && _strnicmp(line_start, "Location:", 9) == 0) {
                const char *v = line_start + 9;
                while (*v == ' ' || *v == '\t') v++;
                size_t vlen = len - (size_t)(v - line_start);
                if (vlen >= sizeof(location)) vlen = sizeof(location) -1 ;
                memcpy(location, v, vlen);
                location[vlen] = '\0';
            }
            fwrite(line_start, 1, len, stdout);
            putchar('\n');
            line_start = line_end + 1;
         //   status_code = atol(raw + 9);
            if (got >= 12 && strncmp(raw, "HTTP/", 5) == 0) {
                status_code = atol(raw + 9); // skip "HTTP/1.1 "
            }

      }
      printf("location = \"%s\"\n\n", location);
      printf("Status_code = %d\n\n", status_code);
      putchar('\n');
      printf("content_length = %d\n\n", content_length);
      printf("content_encoding = \"%s\"\n\n", content_encoding);

      printf("Cookies (%d):\n", cookie_count);
      for (int i = 0; i < cookie_count; i++) {
           printf("   [%d] %s=%s domain=%s path=%s secure=%d expires=%ld\n", i, cookies[i].name, cookies[i].value, cookies[i].domain, cookies[i].path, cookies[i].secure, cookies[i].expires);
      }
      putchar('\n');



      z_stream zs;
      int use_gzip = (strcmp(content_encoding, "gzip") == 0);
      memset(&zs, 0, sizeof(zs));
      if (use_gzip) {
          // 16 + MAX_WBITS = gzip wrapper (auto-detect zlip/gzip)
          if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
              printf("inflateInit2 failed, writing raw bytes\n");
              use_gzip = 0;     
          } else {
              printf("gzip decode enabled\n");
          }
      }
      BrotliDecoderState *br = NULL;
      int use_brotli = (strcmp(content_encoding, "br") == 0);
      if (use_brotli) {
          br = BrotliDecoderCreateInstance(NULL, NULL, NULL);
          if (br == NULL) {
               printf("BrotliDecoderCreateInstance failed, writing raw bytes\n");
               use_brotli = 0;
          } else {
                printf("brotli decode enabled\n");
          }
      }




      int body_start   = header_end + 4;
      int body_bytes   = got - body_start;
      // Body bytes already buffered behind the headers
      if (body_bytes < 0) body_bytes = 0;
      
      FILE *out = (strcmp(out_path, "-") == 0) ? stdout : fopen(out_path, "wb");
      if (out == NULL) {
          printf("Could not open %s for writing\n", out_path);
          if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
          closesocket(sock);
          WSACleanup();
          return 1;
      }
   ///
      if (is_chunked) {
          // Chunked streming state machine. Reads framing byte-by-byte writes chunk data in batches. No fixed buffer, no size cap
          int pos = body_start;
          int buffered_end = got;
          int state = 0; // 0=size, 1=size_lf, 3=data, 4=data_cr, 5=data_lf, 6=done
          int chunk_remaining = 0;
          int hex_acc = 0;
          long total_written = 0;

          while (state != 6) {
                 // Refill buffer when it runs dry
               if (pos >= buffered_end) {
                   int bytes = use_tls ? SSL_read(ssl, buffer, sizeof(buffer) - 1)
                                       : recv(sock, buffer, sizeof(buffer) - 1, 0);
                   if (bytes <= 0) break;
                   memcpy(raw, buffer, bytes);
                   pos = 0;
                   buffered_end = bytes;
               }
     
               if (state == 3) {
                    // Data state: batch-write as much as possible
                    int avail = buffered_end - pos;
                    int to_write = (chunk_remaining < avail) ? chunk_remaining : avail;
                    if (body_write(out, &zs, use_gzip, br, use_brotli, (unsigned char *)(raw + pos), to_write) < 0) { state = 6; break; }
                    pos += to_write;
                    total_written += to_write;
                    chunk_remaining -= to_write;
                    if (chunk_remaining == 0) state = 4;
                    continue;
               }

               // Framing states: consume one byte
               unsigned char c = (unsigned char)raw[pos++];
               if (state == 0) {
                   if (c >= '0' && c <= '9')      hex_acc = hex_acc * 16 + (c - '0');
                   else if (c >= 'a' && c <= 'f') hex_acc = hex_acc * 16 + (c - 'a' + 10);
                   else if (c >= 'A' && c <= 'F') hex_acc = hex_acc * 16 + (c - 'A' + 10);
                   else if (c == ';')             { /*  chunk extension: skip to CR */ }
                   else if (c == '\r')            { chunk_remaining = hex_acc; hex_acc = 0; state = 1;}
                   else { printf("Malformed chunk size\n"); state = 6; }
               } else if (state == 1) {
                   if (c == '\n') state = (chunk_remaining == 0) ? 6 : 3;
                   else { printf("Malformed chunk header\n"); state = 6; }
               } else if (state == 4) {
                   if (c == '\r') state = 5;
                   else { printf("Malformed chunk trailer\n"); state = 6; }
               } else if (state == 5) {
                   if (c == '\n') state = 0;
                   else { printf("Malformed chunk trailer\n"); state = 6; }
               }
          }
          printf("Streamed %ld bytes (chunked) to %s\n", total_written, out_path);

      } else {




          // Content-Length or close-delimited: stream directly to disk
          // No fixed buffer, no size cap
          int written = 0;
           
          if (content_length >= 0) {
              // Flush whatever body came in the same read as the hreaders capped at content_length to be safe
              int init = body_bytes > content_length ? content_length : body_bytes;
              if (init > 0) body_write(out, &zs, use_gzip, br, use_brotli, (unsigned char *)(raw + body_start), init);
              written = init;
              
              
             // Read the rest untill we've sent exactly content_length bytes
              while (written < content_length) {
                   int bytes = use_tls ? SSL_read(ssl, buffer, sizeof(buffer) - 1)
                                       : recv(sock, buffer, sizeof(buffer) - 1, 0);
                   if (bytes <= 0) break;
                   int to_write = bytes;
                   if (written + to_write > content_length) {
                       to_write = content_length - written;
                   }
                   body_write(out, &zs, use_gzip, br, use_brotli, (unsigned char *)buffer, to_write);
                   written += to_write;
              }
              printf("Streamed %d bytes to decoded_body.html\n", written);
          } else {
             // Close-delimited: flush buffered body, then read untill EOF
              if (body_bytes > 0) body_write(out, &zs, use_gzip, br, use_brotli, (unsigned char *)(raw + body_start), body_bytes);
              written = body_bytes;
              // check body_write's return and stop if it failed
              while (1) {
                  int bytes = use_tls ? SSL_read(ssl, buffer, sizeof(buffer) - 1)
                                      : recv(sock, buffer, sizeof(buffer) - 1, 0);
                  if (bytes <= 0) {
                      printf("close-delimited read ended (bytes=%d)\n", bytes);
                      break;
                  }
                  if (body_write(out, &zs, use_gzip, br, use_brotli, (unsigned char *)buffer, bytes) < 0) {
                      printf("body_write failed, stopping read loop\n");
                      break;
                  }
                  written += bytes;
              }
              printf("Streamed %d bytes (close_delimited) to decoded_body.html\n", written);
          }
      }

      if (out != stdout) fclose(out);
      if (use_gzip) inflateEnd(&zs);
      if (use_brotli && br) BrotliDecoderDestroyInstance(br); 
       



        if ((status_code == 301 || status_code == 302 || status_code == 303 || status_code == 307 || status_code == 308) && location[0] != '\0') {

          // per HTTP spec: 301.302/303 downgrade POSt -> GET; 307/308 preserve method+bidy
          if ((status_code == 301 || status_code == 302 || status_code == 303) && strcmp(method, "POST") == 0) {
              method   = "GET";
              body     = "";
              body_len = 0;
              printf("Redirect downgrade POST -> GET (status %d)\n", status_code);
          }
          const char *host_start = NULL ;
          if (strncmp(location, "https://", 8) == 0) {
              host_start = location + 8;
              strcpy(current_port, "443");
              use_tls = 1;
          } else if (strncmp(location, "http://", 7) == 0) {
              host_start = location + 7;
              strcpy(current_port, "80");
              use_tls = 0;
          } else if (location[0] == '/') {
              /* Relative redirect: same host, new path */
              char norm[1024];
              normalize_path(location, norm, sizeof(norm));
              strncpy(current_path, norm, sizeof(current_path) - 1);
              current_path[sizeof(current_path) - 1] = '\0';
              printf("Following relative redirect to path %s\n\n", current_path);
             // closesocket(sock);
              continue;
          } else if (location[0] != '?') {
              /* Bare relative: merge with the directory of the current path */
              const char *last_slash = strrchr(current_path, '/');
              size_t dir_len = (last_slash != NULL)
                               ? (size_t)(last_slash - current_path) + 1
                               : 1;
              char new_path[1024];
              snprintf(new_path, sizeof(new_path), "%.*s%s",
                       (int)dir_len, current_path, location);
              char norm[1024];
              normalize_path(new_path, norm, sizeof(norm));
              strncpy(current_path, norm, sizeof(current_path) - 1);
              current_path[sizeof(current_path) - 1] = '\0';
              printf("following bare relative redirect to path %s\n\n", current_path);
             // closesocket(sock);
              continue;
          }

              // parse host + path out of location
          if (host_start != NULL) {
              const char *path_start = strchr(host_start, '/');
              if (path_start != NULL) {
                  size_t host_len = (size_t)(path_start - host_start);
                  if (host_len >= sizeof(current_host)) host_len = sizeof(current_host) - 1;
                  memcpy(current_host, host_start, host_len);
                  current_host[host_len] = '\0';
                  strncpy(current_path, path_start, sizeof(current_path) - 1);
                  current_path[sizeof(current_path) - 1] = '\0';
              } else {
                  strncpy(current_host, host_start, sizeof(current_host) - 1);
                  current_host[sizeof(current_host) - 1] = '\0';
                  strcpy(current_path,"/");
              }
          
              printf("Following redirect to host=%s path=%s\n\n", current_host, current_path);
              // cleanup current socket, then continue
             // closesocket(sock);
              continue;
          } else {
              printf("Unsupported redirect target: %s\n", location);
          }
      }
      if (content_length < 0 && !is_chunked) {
          // Close-delimited body: we don't know the server id done. cannot safely reuse
          server_said_close = 1;
      }
      if (server_said_close) {
          if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
          if (sock != INVALID_SOCKET) closesocket(sock);
          sock = INVALID_SOCKET;
          conn_host[0] = '\0';
          conn_port[0] = '\0';
          conn_tls = -1;
      }
      break;

     }
     if (ssl) {SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
     if (sock != INVALID_SOCKET) { closesocket(sock); sock = INVALID_SOCKET; }

     if (cookie_count > 0) {
         cookies_save(cookies, cookie_count, COOKIE_FILE);
         printf("Saved %d cookies to %s\n", cookie_count, COOKIE_FILE);
     }
     SSL_CTX_free(ctx);
     WSACleanup();
     return 0;
}
