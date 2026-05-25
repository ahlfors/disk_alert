/*
 * disk_alert.c - 极致轻量磁盘空间告警 + 飞书通知
 *
 * 编译：
 *   gcc -O2 -o disk_alert disk_alert.c                    # 动态 ~20KB
 *   gcc -O2 -static -o disk_alert disk_alert.c            # 静态 glibc ~800KB
 *   musl-gcc -Os -static -s -o disk_alert disk_alert.c    # musl 静态 ~100KB（最小）
 *
 * 用法：
 *   ./disk_alert -w "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
 *   ./disk_alert -t 90 -p / -p /data -w "https://..."
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define DEFAULT_THRESHOLD  85
#define MAX_PATHS          16
#define MAX_MSG            2048
#define MAX_HTTP           4096
#define FEISHU_HOST        "open.feishu.cn"

static int         g_threshold = DEFAULT_THRESHOLD;
static const char *g_paths[MAX_PATHS];
static int         g_npath = 0;
static char        g_webhook[512];
static char        g_wpath[256];   /* webhook 路径部分 */
static char        g_host[128];
static char        g_ip[64];

/* ---- 从 URL 提取路径 ---- */
static void parse_webhook(void)
{
    const char *p = strstr(g_webhook, FEISHU_HOST);
    if (p) snprintf(g_wpath, sizeof(g_wpath), "%s", p + strlen(FEISHU_HOST));
}

/* ---- 主机名：uname() 系统调用，零 fork ---- */
static void get_host(void)
{
    struct utsname u;
    if (uname(&u) == 0) snprintf(g_host, sizeof(g_host), "%s", u.nodename);
    else                 strcpy(g_host, "unknown");
}

/*
 * 获取本机出口 IP
 * 技巧：UDP socket connect 8.8.8.8 → getsockname
 * 不产生任何网络流量（UDP 无实际连接）
 */
static void get_ip(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { strcpy(g_ip, "N/A"); return; }

    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53) };
    inet_pton(AF_INET, "8.8.8.8", &sa.sin_addr);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        struct sockaddr_in lo;
        socklen_t len = sizeof(lo);
        getsockname(fd, (struct sockaddr *)&lo, &len);
        inet_ntop(AF_INET, &lo.sin_addr, g_ip, sizeof(g_ip));
    } else {
        strcpy(g_ip, "N/A");
    }
    close(fd);
}

/* ---- 人类可读的字节数（纯整数位运算，无浮点） ---- */
static void fmt_bytes(unsigned long long b, char *out, int sz)
{
    if      (b >= (1ULL<<30)) snprintf(out, sz, "%llu.%lluG", b>>30, (b&((1ULL<<30)-1))*10>>30);
    else if (b >= (1ULL<<20)) snprintf(out, sz, "%lluM", b>>20);
    else                      snprintf(out, sz, "%lluK", b>>10);
}

/*
 * 检查单个路径，statfs() 系统调用 + 纯整数算术
 * 返回写入 out 的字节数，0 = 正常
 */
static int check(const char *path, char *out, int outsz)
{
    struct statfs sf;
    if (statfs(path, &sf) != 0 || sf.f_blocks == 0) return 0;

    unsigned long long total = (unsigned long long)sf.f_blocks * sf.f_bsize;
    unsigned long long avail = (unsigned long long)sf.f_bavail * sf.f_bsize;
    int pct = (int)(100 - avail * 100 / total);
    if (pct < g_threshold) return 0;

    char as[32], ts[32];
    fmt_bytes(avail, as, sizeof(as));
    fmt_bytes(total, ts, sizeof(ts));
    return snprintf(out, outsz, "  %s  %d%%  总%s  余%s\\n", path, pct, ts, as);
}

/*
 * 发送飞书 HTTPS 消息
 *
 * TLS 策略：pipe 给系统自带的 openssl s_client
 * 好处：
 *   1. 二进制本身不链接 libssl，体积最小
 *   2. 仅在有告警时才 fork 一次（正常时零开销）
 *   3. openssl 是 Ubuntu 必装组件，100% 存在
 */
static int send_feishu(const char *msg)
{
    char body[MAX_MSG];
    int blen = snprintf(body, sizeof(body),
        "{\"msg_type\":\"text\",\"content\":{\"text\":\"%s\"}}", msg);

    char http[MAX_HTTP];
    int hlen = snprintf(http, sizeof(http),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        g_wpath, FEISHU_HOST, blen, body);

    int in[2], out[2];
    if (pipe(in) < 0 || pipe(out) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        close(in[1]); close(out[0]);
        dup2(in[0],  STDIN_FILENO);
        dup2(out[1], STDOUT_FILENO);
        dup2(out[1], STDERR_FILENO);
        close(in[0]); close(out[1]);
        execlp("openssl", "openssl", "s_client",
               "-quiet", "-connect", FEISHU_HOST ":443",
               "-servername", FEISHU_HOST, NULL);
        _exit(127);
    }

    close(in[0]); close(out[1]);
    write(in[1], http, hlen);
    close(in[1]);

    char resp[512];
    int n = read(out[0], resp, sizeof(resp)-1);
    close(out[0]);
    waitpid(pid, NULL, 0);

    if (n > 0) { resp[n]='\0'; if (strstr(resp,"200")||strstr(resp,"ok")) return 0; }
    return -1;
}

/* ---- 参数解析 ---- */
static void parse_args(int argc, char **argv)
{
    int c;
    while ((c = getopt(argc, argv, "t:p:w:h")) != -1) {
        switch (c) {
        case 't': g_threshold = atoi(optarg); break;
        case 'p': if (g_npath < MAX_PATHS) g_paths[g_npath++] = optarg; break;
        case 'w': snprintf(g_webhook, sizeof(g_webhook), "%s", optarg); break;
        default:
            fprintf(stderr, "用法: %s [-t 阈值] [-p 路径]... -w <webhook>\n", argv[0]);
            exit(c=='h' ? 0 : 1);
        }
    }
    if (!g_npath)   { g_paths[0] = "/"; g_npath = 1; }
    if (!g_webhook[0]) {
        fprintf(stderr, "错误: 必须指定 -w <飞书 webhook URL>\n");
        exit(1);
    }
}

/* ============ MAIN ============ */
int main(int argc, char **argv)
{
    parse_args(argc, argv);
    parse_webhook();
    get_host();
    get_ip();

    /* 收集告警 */
    char alerts[MAX_MSG] = "";
    int len = 0;
    for (int i = 0; i < g_npath; i++) {
        char buf[256];
        int n = check(g_paths[i], buf, sizeof(buf));
        if (n > 0 && len + n < (int)sizeof(alerts)) {
            memcpy(alerts + len, buf, n);
            len += n;
        }
    }

    /* 无告警 → 退出。零 fork、零网络、零输出 */
    if (!len) return 0;
    alerts[len] = '\0';

    /* 构造消息（仅在此处才有开销） */
    char message[MAX_MSG];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);

    snprintf(message, sizeof(message),
             "⚠️ %s(%s) 磁盘告警\\n%s检测时间: %s", g_host, g_ip, alerts, ts);

    return send_feishu(message) ? 1 : 0;
}
