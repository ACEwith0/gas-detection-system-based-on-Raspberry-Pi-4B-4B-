import time
import smbus
import sys
import threading
import socket
import os
import psutil
import subprocess
import json
import logging
from pathlib import Path

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/gas_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("GasDetector")

# 配置WiFi热点参数
HOTSPOT_SSID = "GasDetector_Hotspot"
HOTSPOT_PASSWORD = "12345678"
HOTSPOT_IP = "192.168.4.1"  # 树莓派作为热点的默认IP
TCP_PORT = 50000  # 与APP端一致的TCP端口
UDP_PORT = 50001  # 广播使用的UDP端口
BROADCAST_INTERVAL = 5  # 广播间隔（秒）

# 传感器相关全局变量
client_socket = None
sensor_data_lock = threading.Lock()
current_mq2_raw = 0
current_mq9_raw = 0
alert_status = {"smoke": False, "co": False}

# PCF8591设置
PCF8591_ADDRESS = 0x48
PCF8591_CHANNEL_MQ2 = 0  # MQ-2连接在AIN0
PCF8591_CHANNEL_MQ9 = 1  # MQ-9连接在AIN1
bus = smbus.SMBus(1)  # 树莓派4B使用i2c-1

# 传感器校准参数
MQ2_BASE = 92  # 清洁空气中的基准值
MQ9_BASE = 132  # 清洁空气中的基准值
SENSITIVITY = 1.5  # 传感器灵敏度系数

# 气体阈值设置
MQ2_SMOKE_THRESHOLD = 180  # 烟雾阈值 (0-255)
MQ9_CO_THRESHOLD = 170  # 一氧化碳阈值 (0-255)

# UDP广播相关
broadcast_active = True
broadcast_socket = None

# 服务文件路径
SERVICE_FILE_PATH = "/etc/systemd/system/gas_detector.service"
SCRIPT_PATH = os.path.abspath(__file__)

def setup_service():
    """创建systemd服务文件用于开机自启动"""
    if os.path.exists(SERVICE_FILE_PATH):
        logger.info("服务文件已存在，跳过创建")
        return
    
    service_content = f"""[Unit]
Description=Gas Detector Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={os.path.dirname(SCRIPT_PATH)}
ExecStart=/usr/bin/python3 {SCRIPT_PATH}
Restart=always
RestartSec=10
StandardOutput=inherit
StandardError=inherit

[Install]
WantedBy=multi-user.target
"""

    try:
        with open(SERVICE_FILE_PATH, 'w') as f:
            f.write(service_content)
        
        # 设置权限
        os.chmod(SERVICE_FILE_PATH, 0o644)
        
        # 启用服务
        os.system('sudo systemctl daemon-reload')
        os.system('sudo systemctl enable gas_detector.service')
        
        logger.info("已创建并启用systemd服务")
        logger.info("使用以下命令管理服务:")
        logger.info("sudo systemctl start gas_detector.service")
        logger.info("sudo systemctl stop gas_detector.service")
        logger.info("sudo systemctl status gas_detector.service")
        logger.info("sudo journalctl -u gas_detector.service -f")
    except Exception as e:
        logger.error(f"创建服务文件失败: {e}")

def udp_broadcaster():
    """UDP广播线程，定期广播设备信息"""
    global broadcast_socket, broadcast_active
    
    logger.info("启动UDP广播服务...")
    
    try:
        # 创建UDP套接字
        broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        broadcast_socket.settimeout(0.2)
        
        # 创建广播消息
        device_info = {
            "device_name": "气体检测仪",
            "ip_address": HOTSPOT_IP,
            "tcp_port": TCP_PORT,
            "udp_port": UDP_PORT,
            "ssid": HOTSPOT_SSID,
            "sensors": ["MQ-2(烟雾)", "MQ-9(一氧化碳)"]
        }
        message = json.dumps(device_info).encode('utf-8')
        
        # 广播地址 (使用本地广播地址)
        broadcast_address = ('<broadcast>', UDP_PORT)
        
        while broadcast_active:
            try:
                # 发送广播
                broadcast_socket.sendto(message, broadcast_address)
                logger.debug(f"发送UDP广播: {device_info}")
            except Exception as e:
                logger.error(f"发送广播失败: {e}")
            
            # 等待下一次广播
            time.sleep(BROADCAST_INTERVAL)
    except Exception as e:
        logger.error(f"UDP广播错误: {e}")
    finally:
        if broadcast_socket:
            broadcast_socket.close()

def check_wifi_adapter():
    """检查无线适配器是否支持AP模式"""
    try:
        result = subprocess.check_output(["iw", "list"], text=True)
        if "AP" in result:
            logger.info("无线适配器支持AP模式")
            return True
        else:
            logger.warning("无线适配器可能不支持AP模式")
            return False
    except Exception as e:
        logger.error(f"检查无线适配器失败: {e}")
        return False

def setup_wifi_hotspot():
    """配置树莓派为WiFi热点"""
    logger.info("正在配置树莓派为WiFi热点...")
    
    if not check_wifi_adapter():
        logger.error("无法创建热点：无线适配器不支持AP模式")
        return False
    
    try:
        # 1. 停止可能干扰的服务
        os.system('sudo systemctl stop wpa_supplicant 2>/dev/null')
        os.system('sudo systemctl stop dhcpcd 2>/dev/null')
        os.system('sudo systemctl stop hostapd 2>/dev/null')
        os.system('sudo systemctl stop dnsmasq 2>/dev/null')
        time.sleep(2)
        
        # 2. 配置hostapd
        with open('/etc/hostapd/hostapd.conf', 'w') as f:
            f.write(f"""interface=wlan0
driver=nl80211
ssid={HOTSPOT_SSID}
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={HOTSPOT_PASSWORD}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
""")
        
        # 3. 配置hostapd使用新的配置文件
        with open('/etc/default/hostapd', 'w') as f:
            f.write('DAEMON_CONF="/etc/hostapd/hostapd.conf"\n')
        
        # 4. 配置dnsmasq
        with open('/etc/dnsmasq.conf', 'w') as f:
            f.write(f"""interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
""")
        
        # 5. 配置网络接口
        with open('/etc/dhcpcd.conf', 'a') as f:
            f.write(f"""
interface wlan0
static ip_address={HOTSPOT_IP}/24
nohook wpa_supplicant
""")
        
        # 6. 设置IP转发
        with open('/etc/sysctl.conf', 'a') as f:
            f.write("net.ipv4.ip_forward=1\n")
        os.system('sudo sysctl -p')
        
        # 7. 重启网络服务
        os.system('sudo systemctl unmask hostapd')
        os.system('sudo systemctl enable hostapd')
        os.system('sudo systemctl enable dnsmasq')
        os.system('sudo systemctl restart dhcpcd')
        os.system('sudo systemctl restart hostapd')
        os.system('sudo systemctl restart dnsmasq')
        time.sleep(3)  # 给服务启动时间
        
        # 8. 设置防火墙规则
        os.system('sudo iptables -t nat -F')
        os.system('sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')
        os.system('sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT')
        os.system('sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT')
        
        # 9. 配置wlan0接口
        os.system(f'sudo ifconfig wlan0 {HOTSPOT_IP} netmask 255.255.255.0 up')
        
        # 10. 检查服务状态
        hostapd_status = os.system('sudo systemctl is-active --quiet hostapd')
        dnsmasq_status = os.system('sudo systemctl is-active --quiet dnsmasq')
        
        if hostapd_status == 0 and dnsmasq_status == 0:
            logger.info(f"WiFi热点已创建! SSID: {HOTSPOT_SSID}, 密码: {HOTSPOT_PASSWORD}")
            logger.info(f"树莓派IP地址: {HOTSPOT_IP}, 端口: {TCP_PORT}")
            return True
        else:
            logger.error("热点服务启动失败，请检查日志:")
            os.system('sudo journalctl -u hostapd --since "1 minute ago"')
            os.system('sudo journalctl -u dnsmasq --since "1 minute ago"')
            return False
            
    except Exception as e:
        logger.error(f"创建热点失败: {e}")
        return False

def is_port_in_use(port):
    """检查端口是否已被占用"""
    for conn in psutil.net_connections():
        if conn.laddr.port == port:
            return True
    return False

def kill_process_using_port(port):
    """终止使用指定端口的进程"""
    try:
        for conn in psutil.net_connections():
            if conn.laddr.port == port and conn.pid:
                os.system(f"sudo kill -9 {conn.pid}")
                logger.info(f"已终止使用端口 {port} 的进程 (PID: {conn.pid})")
                time.sleep(1)  # 给系统时间释放端口
    except Exception as e:
        logger.error(f"终止进程出错: {e}")

def data_sender():
    """数据发送线程"""
    global client_socket

    while True:
        if client_socket:
            try:
                # 使用锁保护数据访问
                with sensor_data_lock:
                    mq2_val = current_mq2_raw
                    mq9_val = current_mq9_raw
                    smoke_alert = alert_status["smoke"]
                    co_alert = alert_status["co"]

                # 包含报警状态的数据格式
                data_str = f"MQ2_Smoke:{mq2_val},MQ9_Smoke:{mq9_val},SmokeAlert:{1 if smoke_alert else 0},CoAlert:{1 if co_alert else 0}\n"
                client_socket.sendall(data_str.encode('utf-8'))
                time.sleep(0.2)  # 200ms发送间隔
            except Exception as e:
                logger.error(f"发送数据失败: {e}")
                try:
                    client_socket.close()
                except:
                    pass
                client_socket = None
        else:
            time.sleep(1)

def start_tcp_server():
    """启动TCP服务器"""
    global client_socket

    # 检查并释放端口
    if is_port_in_use(TCP_PORT):
        logger.info(f"端口 {TCP_PORT} 已被占用，尝试释放...")
        kill_process_using_port(TCP_PORT)
        time.sleep(2)  # 等待端口释放

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', TCP_PORT))
    except OSError as e:
        logger.error(f"绑定端口失败: {e}")
        logger.info("尝试强制释放端口...")
        kill_process_using_port(TCP_PORT)
        time.sleep(2)
        try:
            server.bind(('0.0.0.0', TCP_PORT))
        except OSError as e2:
            logger.error(f"再次绑定端口失败: {e2}")
            return
    
    server.listen(1)
    logger.info(f"TCP服务器已启动，监听端口: {TCP_PORT}")

    while True:
        try:
            conn, addr = server.accept()
            logger.info(f"客户端连接: {addr}")
            client_socket = conn
            conn.sendall("CONNECTED\n".encode('utf-8'))
        except Exception as e:
            logger.error(f"接受连接错误: {e}")
            if "Bad file descriptor" in str(e):
                break

def read_pcf8591(channel):
    """读取PCF8591指定通道的模拟值"""
    try:
        control_byte = 0x40 | (channel & 0x03)
        bus.write_byte(PCF8591_ADDRESS, control_byte)
        bus.read_byte(PCF8591_ADDRESS)  # 丢弃第一个字节
        value = bus.read_byte(PCF8591_ADDRESS)
        return value
    except Exception as e:
        logger.error(f"读取PCF8591通道{channel}错误: {e}")
        return 0

def main():
    global current_mq2_raw, current_mq9_raw, alert_status, broadcast_active

    # 检查命令行参数
    if "--install-service" in sys.argv:
        setup_service()
        return
    
    logger.info("=" * 60)
    logger.info("气体检测系统启动中...")
    logger.info(f"脚本路径: {SCRIPT_PATH}")
    logger.info(f"服务文件: {SERVICE_FILE_PATH}")
    logger.info("=" * 60)

    # 设置WiFi热点
    if not setup_wifi_hotspot():
        logger.error("无法创建WiFi热点，请检查日志")
        sys.exit(1)

    # 启动UDP广播线程
    broadcast_thread = threading.Thread(target=udp_broadcaster, daemon=True)
    broadcast_thread.start()

    # 启动TCP服务器线程
    server_thread = threading.Thread(target=start_tcp_server, daemon=True)
    server_thread.start()

    # 启动数据发送线程
    sender_thread = threading.Thread(target=data_sender, daemon=True)
    sender_thread.start()

    try:
        last_update = 0
        logger.info("气体检测系统已启动，等待客户端连接...")
        logger.info(f"请连接到热点: {HOTSPOT_SSID}, 密码: {HOTSPOT_PASSWORD}")
        logger.info(f"然后连接到IP: {HOTSPOT_IP}, 端口: {TCP_PORT}")
        logger.info(f"设备将通过UDP广播在端口 {UDP_PORT} 上自动发现")

        while True:
            current_time = time.time()

            # 每秒读取两次传感器数据
            if current_time - last_update > 0.5:
                # 读取传感器数据
                mq2_raw = read_pcf8591(PCF8591_CHANNEL_MQ2)
                mq9_raw = read_pcf8591(PCF8591_CHANNEL_MQ9)

                # 更新全局传感器数据
                with sensor_data_lock:
                    current_mq2_raw = mq2_raw
                    current_mq9_raw = mq9_raw
                    
                # 检测警报条件
                alert_status["smoke"] = mq2_raw > MQ2_SMOKE_THRESHOLD
                alert_status["co"] = mq9_raw > MQ9_CO_THRESHOLD

                # 控制台输出
                smoke_status = "触发!" if alert_status["smoke"] else "正常"
                co_status = "触发!" if alert_status["co"] else "正常"
                logger.info(f"MQ2: {mq2_raw}/255 (烟雾: {smoke_status}), MQ9: {mq9_raw}/255 (CO: {co_status})")

                last_update = current_time

            time.sleep(0.1)  # 减少CPU占用

    except KeyboardInterrupt:
        logger.info("\n正在关闭系统...")
        broadcast_active = False  # 停止广播线程
        
        if client_socket:
            try:
                client_socket.close()
            except:
                pass
        
        # 恢复网络设置
        os.system('sudo systemctl stop hostapd')
        os.system('sudo systemctl stop dnsmasq')
        os.system('sudo systemctl restart dhcpcd')
        
        # 等待广播线程结束
        if broadcast_thread.is_alive():
            broadcast_thread.join(timeout=2.0)
        
        logger.info("系统已关闭")
        sys.exit(0)

if __name__ == "__main__":
    # 检查是否以root权限运行
    if os.geteuid() != 0:
        print("请使用sudo运行此脚本，因为需要配置网络设置")
        sys.exit(1)
    
    # 确保psutil已安装
    try:
        import psutil
    except ImportError:
        print("安装psutil库...")
        os.system('sudo pip3 install psutil')
        import psutil
    
    main()