import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timedelta, timezone
import os
from urllib.parse import urlparse, quote, unquote
import socket
import ssl
import re
from typing import List, Tuple, Set
import logging

# 获取文件路径配置
def get_file_paths():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    return {
        "urls": os.path.join(parent_dir, 'urls.txt'),          # 远程源列表
        "blacklist_auto": os.path.join(current_dir, 'blacklist_auto.txt'),  # 自动生成的失败链接黑名单
        "whitelist_manual": os.path.join(current_dir, 'whitelist_manual.txt'),  # 手动配置的白名单
        "whitelist_auto": os.path.join(current_dir, 'whitelist_auto.txt'),  # 自动生成的有效/白名单链接
        "whitelist_respotime": os.path.join(current_dir, 'whitelist_respotime.txt'),  # 带响应时间的白名单/有效链接
        "log": os.path.join(current_dir, 'log.txt')           # 运行日志
    }

FILE_PATHS = get_file_paths()

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(FILE_PATHS["log"], mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 全局配置类
class Config:
    # 请求头配置
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PotPlayer/1.7.21098"
    USER_AGENT_URL = "okhttp/3.14.9"
    
    # 超时配置（单位：秒）
    TIMEOUT_FETCH = 5       # 拉取远程源超时
    TIMEOUT_CHECK = 2.5     # 链接检测超时
    TIMEOUT_CONNECT = 1.5   # 套接字连接超时
    TIMEOUT_READ = 1.5      # 套接字读取超时
    
    # 并发配置
    MAX_WORKERS = 25        # 最大并发检测线程数
    MAX_RETRIES = 0         # 检测重试次数（0=不重试）

# 链接有效性检测核心类
class AccurateStreamChecker:
    def __init__(self):
        self.start_time = datetime.now()          # 程序启动时间
        self.ipv6_available = self._check_ipv6_support()  # 检测IPv6是否可用
        self.failed_urls = self._load_blacklist()  # 加载历史失败链接（黑名单）

    # 检测IPv6网络是否可用
    def _check_ipv6_support(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('2001:4860:4860::8888', 53))  # 谷歌DNS IPv6地址
            sock.close()
            return result == 0
        except:
            return False

    # 加载blacklist_auto中的历史失败链接
    def _load_blacklist(self) -> Set[str]:
        failed_set = set()
        try:
            if os.path.exists(FILE_PATHS["blacklist_auto"]):
                with open(FILE_PATHS["blacklist_auto"], 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # 过滤有效链接行（包含,和://）
                        if line and ',' in line and '://' in line:
                            parts = line.split(',')
                            url = parts[-1].strip()
                            # 仅保留http/rtmp/rtsp协议的链接
                            if url.startswith(('http', 'rtmp', 'rtsp')):
                                failed_set.add(url)
                logger.info(f"加载历史失败链接: {len(failed_set)} 个")
        except Exception as e:
            logger.error(f"加载黑名单失败: {e}")
        return failed_set

    # 读取文本文件，返回非空行列表
    def read_txt(self, file_path: str) -> List[str]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []

    # 创建SSL上下文（兼容老旧证书）
    def create_ssl_context(self):
        context = ssl.create_default_context()
        context.check_hostname = False    # 关闭主机名验证
        context.verify_mode = ssl.CERT_NONE  # 不验证证书
        context.set_ciphers('DEFAULT:@SECLEVEL=1')  # 降低安全级别兼容老旧服务
        return context

    # 检测HTTP/HTTPS链接有效性，返回(是否有效, 响应时间ms)
    def check_http_url(self, url: str, timeout: int) -> Tuple[bool, float]:
        start_time = time.perf_counter()
        try:
            headers = {
                "User-Agent": Config.USER_AGENT,
                "Accept": "*/*",
                "Referer": "https://iptv-org.github.io/",
                "Connection": "close",
                "Range": "bytes=0-512"  # 仅请求前512字节，加快检测
            }
            req = urllib.request.Request(url, headers=headers, method="HEAD")  # HEAD请求更轻量
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self.create_ssl_context()),
                urllib.request.HTTPRedirectHandler()  # 自动跟随重定向
            )
            with opener.open(req, timeout=timeout) as resp:
                elapsed = (time.perf_counter() - start_time) * 1000
                # 200-499状态码视为有效（包含302重定向、403权限等）
                return 200 <= resp.getcode() < 500, round(elapsed, 2)
        except urllib.error.HTTPError as e:
            elapsed = (time.perf_counter() - start_time) * 1000
            # 302/403/404仍视为有效（链接可达但内容异常）
            return e.code in [302, 403, 404], round(elapsed, 2)
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    # 检测RTMP/RTSP链接有效性，返回(是否有效, 响应时间ms)
    def check_rtmp_rtsp_url(self, url: str, timeout: int) -> Tuple[bool, float]:
        start_time = time.perf_counter()
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                elapsed = (time.perf_counter() - start_time) * 1000
                return False, round(elapsed, 2)
            # 自动识别默认端口：RTMP=1935，RTSP=554
            port = parsed.port or (1935 if url.startswith('rtmp') else 554)
            
            # 解析域名（支持IPv4/IPv6）
            addr_info = socket.getaddrinfo(parsed.hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for res in addr_info:
                af, socktype, proto, _, sa = res
                sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    sock.settimeout(min(Config.TIMEOUT_CONNECT, timeout))
                    sock.connect(sa)  # 仅检测端口连通性
                    
                    # RTMP简单检测：发送握手包首字节
                    if url.startswith('rtmp'):
                        sock.send(b'\x03')
                        sock.settimeout(Config.TIMEOUT_READ)
                        data = sock.recv(1)
                        elapsed = (time.perf_counter() - start_time) * 1000
                        return bool(data), round(elapsed, 2)
                    # RTSP简单检测：发送OPTIONS请求
                    elif url.startswith('rtsp'):
                        req = f"OPTIONS {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {Config.USER_AGENT}\r\n\r\n"
                        sock.send(req.encode())
                        sock.settimeout(Config.TIMEOUT_READ)
                        resp = sock.recv(1024)
                        elapsed = (time.perf_counter() - start_time) * 1000
                        return b'RTSP/1.0' in resp, round(elapsed, 2)
                    elapsed = (time.perf_counter() - start_time) * 1000
                    return True, round(elapsed, 2)
                except:
                    continue
                finally:
                    if sock:
                        sock.close()
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    # 统一链接检测入口，自动识别协议
    def check_url(self, url: str) -> Tuple[bool, float]:
        try:
            # 解码URL中的特殊字符，避免检测失败
            encoded_url = quote(unquote(url), safe=':/?&=#')
            timeout = Config.TIMEOUT_CHECK
            
            if url.startswith(("http://", "https://")):
                return self.check_http_url(encoded_url, timeout)
            elif url.startswith(("rtmp://", "rtsp://")):
                return self.check_rtmp_rtsp_url(encoded_url, timeout)
            else:
                # 其他协议仅检测端口连通性
                start_time = time.perf_counter()
                parsed = urlparse(url)
                if not parsed.hostname:
                    elapsed = (time.perf_counter() - start_time) * 1000
                    return False, round(elapsed, 2)
                port = parsed.port or 80
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.TIMEOUT_CONNECT)
                sock.connect((parsed.hostname, port))
                sock.close()
                elapsed = (time.perf_counter() - start_time) * 1000
                return True, round(elapsed, 2)
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    # 拉取远程源中的链接列表
    def fetch_remote_urls(self, urls: List[str]) -> List[str]:
        all_lines = []
        for url in urls:
            try:
                req = urllib.request.Request(
                    quote(unquote(url), safe=':/?&=#'),
                    headers={"User-Agent": Config.USER_AGENT_URL}
                )
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT_FETCH) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    # 识别M3U文件格式
                    if "#EXTM3U" in content:
                        lines = self._parse_m3u(content)
                    else:
                        # 普通文本：过滤出包含://的有效链接行（名称,链接格式）
                        lines = [line.strip() for line in content.split('\n') if line.strip() and '://' in line and ',' in line]
                    all_lines.extend(lines)
                    logger.info(f"从 {url} 获取 {len(lines)} 个候选链接")
            except Exception as e:
                logger.error(f"拉取远程源失败 {url}: {e}")
        return all_lines

    # 解析M3U文件，提取名称和链接
    def _parse_m3u(self, content: str) -> List[str]:
        lines = []
        current_name = ""
        for line in content.split('\n'):
            line = line.strip()
            # 提取EXTINF后的名称
            if line.startswith("#EXTINF"):
                match = re.search(r',(.+)$', line)
                if match:
                    current_name = match.group(1).strip()
            # 提取实际链接并拼接名称
            elif line.startswith(('http://', 'https://', 'rtmp://', 'rtsp://')) and current_name:
                lines.append(f"{current_name},{line}")
        return lines

    # 清洗链接：去重 + 过滤历史失败链接
    def clean_deduplicate(self, lines: List[str]) -> List[str]:
        seen_urls = set()
        cleaned = []
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
            name, url = line.split(',', 1)
            url = url.strip().split('#')[0].split('$')[0]  # 移除URL后的锚点/参数
            
            # 过滤历史失败链接，直接跳过检测
            if url in self.failed_urls:
                continue
            
            # 去重：同一URL仅保留第一条
            if url not in seen_urls:
                seen_urls.add(url)
                cleaned.append(f"{name},{url}")
        logger.info(f"清洗+过滤历史失败链接后剩余 {len(cleaned)} 个待检测链接")
        return cleaned

    # 批量并发检测链接有效性
    def batch_check(self, lines: List[str], whitelist: Set[str]) -> Tuple[List[Tuple[str, float]], List[str]]:
        success = []  # 有效链接 + 白名单链接（无论是否有效）
        failed = []   # 非白名单失败链接
        logger.info(f"开始检测 {len(lines)} 个链接的有效性")

        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            # 提交所有检测任务
            futures = {}
            for line in lines:
                if ',' in line:
                    _, url = line.split(',', 1)
                    url = url.strip()
                    futures[executor.submit(self.check_url, url)] = (line, url)

            # 处理检测结果
            processed = 0
            for future in as_completed(futures):
                line, url = futures[future]
                processed += 1
                try:
                    is_valid, resp_time = future.result()
                    
                    # 核心逻辑：先处理有效链接，再处理无效特例
                    if is_valid:
                        success.append((line, resp_time))
                    else:
                        # 白名单链接：失败则响应时间设为0.00，仍加入success
                        if url in whitelist:
                            success.append((line, 0.00))
                        # 非白名单链接：失败则加入failed
                        else:
                            failed.append(line)
                    
                except Exception as e:
                    # 检测异常处理：白名单保留（0.00ms），非白名单归为失败
                    if url in whitelist:
                        success.append((line, 0.00))
                        logger.error(f"白名单链接检测异常，设为0.00ms: {url} | 错误: {e}")
                    else:
                        failed.append(line)
                
                # 每检测100个链接打印进度
                if processed % 100 == 0 or processed == len(lines):
                    logger.info(f"进度: {processed}/{len(lines)} | 有效/白名单: {len(success)} | 无效: {len(failed)}")

        # 按响应时间升序排序（更快的链接在前）
        success_sorted = sorted(success, key=lambda x: x[1])
        logger.info(f"有效性检测完成 - 有效/白名单链接 {len(success)} 个 | 无效链接 {len(failed)} 个")
        return success_sorted, failed

    # 保存检测结果到文件
    def save_results(self, success: List[Tuple[str, float]], failed: List[str]):
        # 生成北京时间的版本戳
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"

        # 保存带响应时间的有效/白名单链接
        success_resp = [
            "更新时间,#genre#", version, "", "RespoTime,whitelist,#genre#"
        ] + [f"{resp_time:.2f}ms,{line}" for line, resp_time in success]
        
        # 保存纯有效/白名单链接（无响应时间）
        success_clean = [
            "更新时间,#genre#", version, "", "whitelist,#genre#"
        ] + [line for line, _ in success]
        
        # 保存失败链接（非白名单）
        failed_clean = [
            "更新时间,#genre#", version, "", "blacklist,#genre#"
        ] + failed

        # 写入文件（自动创建目录）
        self._write_file(FILE_PATHS["whitelist_respotime"], success_resp)
        self._write_file(FILE_PATHS["whitelist_auto"], success_clean)
        self._write_file(FILE_PATHS["blacklist_auto"], failed_clean)
        logger.info(f"有效性检测结果已保存")

    # 通用文件写入方法
    def _write_file(self, file_path: str, data: List[str]):
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(data))
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")

    # 主执行流程
    def run(self):
        logger.info("===== 链接有效性检测开始 =====")
        
        # 1. 拉取远程源链接
        remote_urls = self.read_txt(FILE_PATHS["urls"])
        all_lines = self.fetch_remote_urls(remote_urls)
        
        # 2. 加载并处理白名单（确保白名单必检测）
        whitelist_raw = self.read_txt(FILE_PATHS["whitelist_manual"])
        whitelist_lines = self.clean_deduplicate(whitelist_raw)
        whitelist = set()
        whitelist_full_lines = []  # 保存白名单完整行（名称+链接）
        for line in whitelist_lines:
            if ',' in line:
                name, url = line.split(',', 1)
                url = url.strip()
                whitelist.add(url)
                whitelist_full_lines.append(line)
        logger.info(f"白名单有效链接数: {len(whitelist)}")
        
        # 3. 合并候选链接 + 白名单（避免白名单被历史失败链接过滤）
        all_lines += whitelist_full_lines
        cleaned_lines = self.clean_deduplicate(all_lines)
        
        # 4. 批量检测链接有效性
        valid_links, invalid_links = self.batch_check(cleaned_lines, whitelist)
        
        # 5. 保存检测结果
        self.save_results(valid_links, invalid_links)
        
        # 6. 打印统计信息
        elapsed = datetime.now() - self.start_time
        logger.info("===== 链接有效性检测完成 =====")
        logger.info(f"总耗时: {elapsed.total_seconds():.1f} 秒")
        logger.info(f"最终有效/白名单链接: {len(valid_links)} 个 | 无效链接: {len(invalid_links)} 个")

# 程序入口
if __name__ == "__main__":
    checker = AccurateStreamChecker()
    try:
        checker.run()
    except KeyboardInterrupt:
        logger.info("检测被用户中断")
    except Exception as e:
        logger.error(f"检测出错: {e}", exc_info=True)
    finally:
        logger.info("检测结束")
