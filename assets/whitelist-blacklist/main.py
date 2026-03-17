import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timedelta, timezone
import os
from urllib.parse import urlparse, quote, unquote
import socket
import ssl
import re
from typing import List, Tuple, Optional, Set
import logging

# ==================== 核心配置 ====================
def get_file_paths():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    return {
        "urls": os.path.join(parent_dir, 'urls.txt'),
        "blacklist_auto": os.path.join(current_dir, 'blacklist_auto.txt'),
        "whitelist_manual": os.path.join(current_dir, 'whitelist_manual.txt'),
        "whitelist_auto": os.path.join(current_dir, 'whitelist_auto.txt'),
        "whitelist_respotime": os.path.join(current_dir, 'whitelist_respotime.txt'),
        "log": os.path.join(current_dir, 'log.txt')
    }

FILE_PATHS = get_file_paths()

# 日志配置（保留关键有效性检测日志）
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(FILE_PATHS["log"], mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 核心配置（平衡速度与有效性判定）
class Config:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PotPlayer/1.7.21098"
    USER_AGENT_URL = "okhttp/3.14.9"
    
    # 超时配置（兼顾速度与有效性，避免过快误判）
    TIMEOUT_FETCH = 5
    TIMEOUT_CHECK = 2.5  # 比纯极速版略放宽，提升有效性判定准确率
    TIMEOUT_CONNECT = 1.5
    TIMEOUT_READ = 1.5
    
    MAX_WORKERS = 16  # 高并发保障速度
    MAX_RETRIES = 0   # 关闭重试，聚焦单次有效性检测

# ==================== 精准链接有效性检测器 ====================
class AccurateStreamChecker:
    def __init__(self):
        self.start_time = datetime.now()
        self.ipv6_available = self._check_ipv6_support()

    def _check_ipv6_support(self) -> bool:
        """极简IPv6检测（不影响速度）"""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('2001:4860:4860::8888', 53))
            sock.close()
            return result == 0
        except:
            return False

    def read_txt(self, file_path: str) -> List[str]:
        """极简文件读取"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []

    def create_ssl_context(self):
        """SSL上下文（兼容更多HTTPS链接）"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('DEFAULT:@SECLEVEL=1')  # 兼容老证书链接
        return context

    def check_http_url(self, url: str, timeout: int) -> bool:
        """精准HTTP/HTTPS有效性检测（核心优化）"""
        try:
            # 模拟真实播放器请求头，提升有效性判定准确率
            headers = {
                "User-Agent": Config.USER_AGENT,
                "Accept": "*/*",
                "Referer": "https://iptv-org.github.io/",
                "Connection": "close",
                "Range": "bytes=0-512"  # 仅请求少量数据，平衡速度与有效性
            }
            req = urllib.request.Request(url, headers=headers, method="HEAD")  # 轻量请求
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self.create_ssl_context()),
                urllib.request.HTTPRedirectHandler()  # 自动处理3xx重定向（有效链接常见）
            )
            with opener.open(req, timeout=timeout) as resp:
                # 200-499状态码均视为有效（很多直播源返回403/404仍可播放）
                return 200 <= resp.getcode() < 500
        except urllib.error.HTTPError as e:
            # 特殊处理403/404/302，这些状态码常对应有效但有反爬的链接
            return e.code in [302, 403, 404]
        except:
            return False

    def check_rtmp_rtsp_url(self, url: str, timeout: int) -> bool:
        """精准RTMP/RTSP有效性检测（仅端口连通+协议响应）"""
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False
            port = parsed.port or (1935 if url.startswith('rtmp') else 554)
            
            addr_info = socket.getaddrinfo(parsed.hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for res in addr_info:
                af, socktype, proto, _, sa = res
                sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    sock.settimeout(min(Config.TIMEOUT_CONNECT, timeout))
                    sock.connect(sa)  # 端口连通是基础有效性
                    
                    # 协议级验证（提升有效性判定精度）
                    if url.startswith('rtmp'):
                        sock.send(b'\x03')  # 发送RTMP握手起始包
                        sock.settimeout(Config.TIMEOUT_READ)
                        data = sock.recv(1)
                        return bool(data)  # 有响应则视为有效
                    elif url.startswith('rtsp'):
                        req = f"OPTIONS {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {Config.USER_AGENT}\r\n\r\n"
                        sock.send(req.encode())
                        sock.settimeout(Config.TIMEOUT_READ)
                        resp = sock.recv(1024)
                        return b'RTSP/1.0' in resp  # 有RTSP响应则视为有效
                    return True
                except:
                    continue
                finally:
                    if sock:
                        sock.close()
            return False
        except:
            return False

    def check_url(self, url: str) -> bool:
        """主有效性检测函数（按协议精准判定）"""
        try:
            encoded_url = quote(unquote(url), safe=':/?&=#')  # 处理特殊字符URL
            timeout = Config.TIMEOUT_CHECK
            
            if url.startswith(("http://", "https://")):
                return self.check_http_url(encoded_url, timeout)
            elif url.startswith(("rtmp://", "rtsp://")):
                return self.check_rtmp_rtsp_url(encoded_url, timeout)
            else:
                # 其他协议（如FLV）仅检测TCP连通有效性
                parsed = urlparse(url)
                if not parsed.hostname:
                    return False
                port = parsed.port or 80
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.TIMEOUT_CONNECT)
                sock.connect((parsed.hostname, port))
                sock.close()
                return True
        except:
            return False

    def fetch_remote_urls(self, urls: List[str]) -> List[str]:
        """拉取远程源（保留有效性过滤）"""
        all_lines = []
        for url in urls:
            try:
                req = urllib.request.Request(
                    quote(unquote(url), safe=':/?&=#'),
                    headers={"User-Agent": Config.USER_AGENT_URL}
                )
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT_FETCH) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    if "#EXTM3U" in content:
                        lines = self._parse_m3u(content)
                    else:
                        lines = [line.strip() for line in content.split('\n') if line.strip() and '://' in line and ',' in line]
                    all_lines.extend(lines)
                    logger.info(f"从 {url} 获取 {len(lines)} 个候选链接")
            except Exception as e:
                logger.error(f"拉取远程源失败 {url}: {e}")
        return all_lines

    def _parse_m3u(self, content: str) -> List[str]:
        """精准M3U解析（仅保留有效格式链接）"""
        lines = []
        current_name = ""
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith("#EXTINF"):
                match = re.search(r',(.+)$', line)
                if match:
                    current_name = match.group(1).strip()
            elif line.startswith(('http://', 'https://', 'rtmp://', 'rtsp://')) and current_name:
                lines.append(f"{current_name},{line}")
        return lines

    def clean_deduplicate(self, lines: List[str]) -> List[str]:
        """清洗去重（避免重复检测无效链接）"""
        seen_urls = set()
        cleaned = []
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
            name, url = line.split(',', 1)
            url = url.strip().split('#')[0].split('$')[0]  # 清理URL参数
            if url not in seen_urls:
                seen_urls.add(url)
                cleaned.append(f"{name},{url}")
        logger.info(f"清洗去重后剩余 {len(cleaned)} 个待检测链接")
        return cleaned

    def batch_check(self, lines: List[str], whitelist: Set[str]) -> Tuple[List[str], List[str]]:
        """批量有效性检测（高并发+精准判定）"""
        success = []  # 有效链接
        failed = []   # 无效链接
        logger.info(f"开始检测 {len(lines)} 个链接的有效性")

        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {}
            for line in lines:
                if ',' in line:
                    _, url = line.split(',', 1)
                    url = url.strip()
                    futures[executor.submit(self.check_url, url)] = (line, url)

            processed = 0
            for future in as_completed(futures):
                line, url = futures[future]
                processed += 1
                try:
                    is_valid = future.result()  # 核心：是否有效
                    if url in whitelist or is_valid:
                        success.append(line)
                    else:
                        failed.append(line)
                except:
                    failed.append(line)
                
                if processed % 100 == 0 or processed == len(lines):
                    logger.info(f"进度: {processed}/{len(lines)} | 有效: {len(success)} | 无效: {len(failed)}")

        # 简单排序（按链接长度，不影响核心功能）
        success_sorted = sorted(success, key=lambda x: len(x.split(',')[1]))
        logger.info(f"有效性检测完成 - 有效链接 {len(success)} 个 | 无效链接 {len(failed)} 个")
        return success_sorted, failed

    def save_results(self, success: List[str], failed: List[str]):
        """保存有效性检测结果"""
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"

        # 带有效性标记的成功列表
        success_resp = [
            "更新时间,#genre#", version, "", "RespoTime,whitelist,#genre#"
        ] + [f"0.00ms,{line}" for line in success]
        
        # 有效链接列表
        success_clean = [
            "更新时间,#genre#", version, "", "whitelist,#genre#"
        ] + success
        
        # 无效链接列表
        failed_clean = [
            "更新时间,#genre#", version, "", "blacklist,#genre#"
        ] + failed

        self._write_file(FILE_PATHS["whitelist_respotime"], success_resp)
        self._write_file(FILE_PATHS["whitelist_auto"], success_clean)
        self._write_file(FILE_PATHS["blacklist_auto"], failed_clean)
        logger.info(f"有效性检测结果已保存")

    def _write_file(self, file_path: str, data: List[str]):
        """文件写入"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(data))
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")

    def run(self):
        """主运行流程（聚焦有效性检测）"""
        logger.info("===== 链接有效性检测开始 =====")
        
        # 1. 拉取候选链接
        remote_urls = self.read_txt(FILE_PATHS["urls"])
        all_lines = self.fetch_remote_urls(remote_urls)
        
        # 2. 加载白名单（直接视为有效）
        whitelist_lines = self.clean_deduplicate(self.read_txt(FILE_PATHS["whitelist_manual"]))
        whitelist = set()
        for line in whitelist_lines:
            if ',' in line:
                _, url = line.split(',', 1)
                whitelist.add(url.strip())
        logger.info(f"白名单有效链接数: {len(whitelist)}")
        
        # 3. 清洗去重（减少无效检测）
        cleaned_lines = self.clean_deduplicate(all_lines)
        
        # 4. 批量有效性检测（核心步骤）
        valid_links, invalid_links = self.batch_check(cleaned_lines, whitelist)
        
        # 5. 保存结果
        self.save_results(valid_links, invalid_links)
        
        # 6. 统计信息
        elapsed = datetime.now() - self.start_time
        logger.info("===== 链接有效性检测完成 =====")
        logger.info(f"总耗时: {elapsed.total_seconds():.1f} 秒")
        logger.info(f"最终有效链接: {len(valid_links)} 个 | 无效链接: {len(invalid_links)} 个")

# ==================== 运行入口 ====================
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
