# Disk Alert

```
C 程序启动 (~50μs)
  ├─ uname()        → 内核直接返回      (系统调用)
  ├─ UDP socket     → getsockname()     (零网络流量)
  ├─ statfs("/")    → 内核直接返回      (系统调用)
  ├─ 整数比较       → 未超阈值
  └─ return 0       → 退出
      
总耗时: < 0.1ms | fork: 0 | 网络: 0 | 磁盘 IO: 0
```

# Build

```
# ========== 方式一：常规编译（推荐） ==========
gcc -O2 -o disk_alert disk_alert.c
# 产物 ~20KB，依赖系统 glibc（Ubuntu 必有）
# ========== 方式二：glibc 静态编译 ==========
gcc -O2 -static -o disk_alert disk_alert.c
strip disk_alert
# 产物 ~750KB，完全独立
# ========== 方式三：musl 极限压缩（推荐） ==========
sudo apt install musl-tools
musl-gcc -Os -static -s -o disk_alert disk_alert.c
# 产物 ~30KB！！！最小二进制
# ========== 查看体积 ==========
ls -lh disk_alert
```

# Run

```
# 基本用法
./disk_alert -w "https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_TOKEN"

# 自定义阈值 + 多路径
./disk_alert -t 90 -p / -p /data -p /home \
  -w "https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_TOKEN"
```
