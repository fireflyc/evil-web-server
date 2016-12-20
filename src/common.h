#ifndef EVIL_WEB_SERVER_COMMON_H
#define EVIL_WEB_SERVER_COMMON_H


#define log_error(...) fprintf(stderr, __VA_ARGS__)
#define log_info(...) fprintf(stdout, __VA_ARGS__)
typedef struct _web_server {
    uint16_t ipid;
    uint32_t seq;
    in_addr_t ip;
    char *hw_addr;
    char *ifi;
} web_server_t;

#endif //EVIL_WEB_SERVER_COMMON_H
