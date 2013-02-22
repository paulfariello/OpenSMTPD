/*
 * Copyright (c) 2013 Paul Fariello <paul@fariello.eu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "sasl.h"

#define SERVICE "smtp"
#define SASLAUTH_PATH "/var/sasl2/mux"

static size_t	sasl_build_query(char **, char *, char *, char *, char *);
static int	sasl_query(const char *, size_t, char **, size_t *, const char *);

static size_t
sasl_build_query(char **query, char *authid, char *password, char *service, char *realm)
{
    char *query_end;
    size_t query_len = 0;
    size_t authid_len, password_len, service_len, realm_len;
    unsigned short authid_count, password_count, service_count, realm_count;
    authid_len = strlen(authid);
    password_len = strlen(password);
    service_len = strlen(service);
    realm_len = strlen(realm);

    query_len = authid_len + password_len + service_len + realm_len + 4 * sizeof(unsigned short);

    query_end = *query = (char *)malloc(query_len);

    authid_count = htons(authid_len);
    password_count = htons(password_len);
    service_count = htons(service_len);
    realm_count = htons(realm_len);

    memcpy(query_end, &authid_count, sizeof(unsigned short));
    query_end += sizeof(unsigned short);

    while (*authid) *query_end++ = *authid++;

    memcpy(query_end, &password_count, sizeof(unsigned short));
    query_end += sizeof(unsigned short);

    while (*password) *query_end++ = *password++;

    memcpy(query_end, &service_count, sizeof(unsigned short));
    query_end += sizeof(unsigned short);

    while (*service) *query_end++ = *service++;

    memcpy(query_end, &realm_count, sizeof(unsigned short));
    query_end += sizeof(unsigned short);

    while (*realm) *query_end++ = *realm++;

    return query_end - *query;
}

static int
sasl_query(const char *query, size_t query_len, char **response, size_t *response_len, const char *socket_path)
{
    int ret = 0;
    unsigned short count;
    int sockfd;
    struct sockaddr_un sockaddr;

    *response = NULL;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_warnx("Cannot open socket: %s (errno %d)", strerror(errno), errno);
        return -1;
    }

    sockaddr.sun_family = AF_UNIX;
    strncpy(sockaddr.sun_path, socket_path, sizeof(sockaddr.sun_path));

    if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        log_warnx("Cannot connect to sasl server: %s (errno %d)", strerror(errno), errno);
        ret = -1;
        goto clean;
    }

    if (send(sockfd, query, query_len, 0) == -1) {
        log_warnx("Cannot send query to sasl server: %s (errno %d)", strerror(errno), errno);
        ret = -1;
        goto clean;
    }

    if (read(sockfd, &count, sizeof(count)) != sizeof(count)) {
        log_warnx("Cannot read sasl server response: %s (errno %d)", strerror(errno), errno);
        ret = -1;
        goto clean;
    }
    count = ntohs(count);

    *response = (char *)malloc((size_t)count + 1);
    if (read(sockfd, *response, count) != count) {
        log_warnx("Cannot read sasl server response: %s (errno %d)", strerror(errno), errno);
        ret = -1;
        goto clean;
    }

    (*response)[count] = '\0';

clean:
    close(sockfd);
    return ret;
}

int
auth_sasl(char *username, char *password)
{
    int ret = 0;
    size_t query_len, response_len;
    char *query, *response;
    char *authid = username;
    char *realm = strchr(username, '@');
    *realm++ = '\0';

    query_len = sasl_build_query(&query, authid, password, SERVICE, realm);

    if (sasl_query(query, query_len, &response, &response_len, SASLAUTH_PATH) < 0)
        goto clean;

    if (!strncmp(response, "OK", 2))
        ret = 1;

clean:
    free(query);
    free(response);

    return ret;
}
