import requests
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
import hashlib
from datetime import datetime
import yaml
import os
import logging
import sys
import signal
from collections import OrderedDict

# 配置日志
log_file = os.path.join(os.path.dirname(__file__), 'php_exporter.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, encoding='utf-8')
    ]
)
logger = logging.getLogger('php-fpm-exporter')


class ConfigLoader:
    def __init__(self, config_path='config.yaml'):
        self.config_path = config_path
        self.config = None
        self.last_modified = 0
        self.lock = threading.Lock()

    def load_config(self):
        """加载并验证配置文件"""
        try:
            with self.lock:
                if not os.path.exists(self.config_path):
                    raise FileNotFoundError(f"Config file not found: {self.config_path}")

                current_modified = os.path.getmtime(self.config_path)
                if current_modified == self.last_modified:
                    return self.config

                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)

                self.validate_config(config)

                self.config = config
                self.last_modified = current_modified
                logger.info(f"Successfully loaded configuration from {self.config_path}")
                return config

        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            if self.config:
                logger.warning("Using previous configuration due to load error")
                return self.config
            raise

    def validate_config(self, config):
        """验证配置结构"""
        required_keys = ['scrape_interval', 'listen_port']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required config key: {key}")

        if not isinstance(config['scrape_interval'], int) or config['scrape_interval'] <= 0:
            raise ValueError("scrape_interval must be a positive integer")

        if not isinstance(config['listen_port'], int) or config['listen_port'] <= 0:
            raise ValueError("listen_port must be a positive integer")


class PhpFpmMetrics:
    def __init__(self, config):
        self.metrics_cache = OrderedDict()
        self.lock = threading.Lock()
        self.running = True
        self.cache_ttl = config.get('cache_ttl', 60)  # 指标缓存时间（秒）
        self.max_cache_size = config.get('max_cache_size', 100)
        self.request_counter = 0
        self.error_counter = 0

    def fetch_metrics(self, url):
        """获取 PHP-FPM 指标"""
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Error fetching {url}: {str(e)}")
            return None

    def parse_metrics(self, data):
        """解析 PHP-FPM 指标"""
        metrics = {}
        for line in data.splitlines():
            if ':' not in line:
                continue
            key, value = line.split(':', 1)
            key = key.strip().replace(' ', '_').lower()
            value = value.strip()

            try:
                # 转换数值型数据
                if key in ['accepted_conn', 'listen_queue', 'max_listen_queue',
                           'idle_processes', 'active_processes', 'total_processes',
                           'max_active_processes', 'max_children_reached', 'slow_requests',
                           'listen_queue_len', 'start_since']:
                    metrics[key] = int(value)
                # 处理时间格式
                elif key == 'start_time':
                    try:
                        dt = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
                        metrics['start_timestamp'] = dt.timestamp()
                    except ValueError:
                        metrics['start_timestamp'] = 0
                else:
                    metrics[key] = value
            except ValueError:
                metrics[key] = value

        return metrics

    def get_metrics(self, target):
        """获取指标（支持缓存）"""
        cache_key = hashlib.md5(target.encode()).hexdigest()
        now = time.time()

        with self.lock:
            # 清理过期缓存
            self._clean_expired_cache(now)

            # 检查缓存
            if cache_key in self.metrics_cache:
                cached = self.metrics_cache[cache_key]
                if (now - cached['timestamp']) < self.cache_ttl:
                    # 更新访问时间
                    self.metrics_cache.move_to_end(cache_key)
                    return cached['metrics']

            # 获取新指标
            data = self.fetch_metrics(target)
            if not data:
                return None

            metrics = self.parse_metrics(data)
            metrics['target'] = target
            metrics['scrape_timestamp'] = now

            # 更新缓存
            self.metrics_cache[cache_key] = {
                'timestamp': now,
                'metrics': metrics
            }

            # 确保缓存不超过最大大小
            if len(self.metrics_cache) > self.max_cache_size:
                self.metrics_cache.popitem(last=False)
            return metrics

    def _clean_expired_cache(self, current_time):
        """清理过期缓存"""
        expired_keys = []
        for key, entry in self.metrics_cache.items():
            if (current_time - entry['timestamp']) > self.cache_ttl:
                expired_keys.append(key)

        for key in expired_keys:
            del self.metrics_cache[key]

    def stop(self):
        self.running = False

    def increment_request_counter(self):
        with self.lock:
            self.request_counter += 1

    def increment_error_counter(self):
        with self.lock:
            self.error_counter += 1


class PhpFpmMetricsHandler(BaseHTTPRequestHandler):
    # 移除__init__方法，使用类方法设置metrics_collector
    @classmethod
    def create(cls, metrics_collector, config):
        cls.metrics_collector = metrics_collector
        cls.config = config
        return cls

    def do_GET(self):
        try:
            # 使用类属性访问metrics_collector
            metrics_collector = self.__class__.metrics_collector

            if metrics_collector is None:
                logger.error("Metrics collector not initialized")
                self.send_error(500, "Internal Server Error: Metrics collector not initialized")
                return

            # 记录请求计数
            metrics_collector.increment_request_counter()
            # 处理探测请求
            if self.path.startswith('/probe'):
                self.handle_probe_request(metrics_collector)
            # 处理健康极
            elif self.path == '/health':
                self.handle_health_check()
            # 暴露自身指标
            elif self.path == '/metrics':
                self.handle_self_metrics(metrics_collector)
            # 其他路径
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
        except Exception as e:
            logger.error(f"Error handling request: {str(e)}")
            # 安全地尝试获取 metrics_collector
            try:
                mc = self.__class__.metrics_collector
                if mc is not None:
                    mc.increment_error_counter()
            except AttributeError:
                pass  # 如果 metrics_collector 完全未定义

            self.send_error(500, "Internal Server Error")

    def handle_probe_request(self, metrics_collector):
        """处理指标探测请求"""
        # 解析查询参数
        query = parse_qs(urlparse(self.path).query)
        target = query.get('target', [''])[0]

        if not target:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing target parameter")
            return

        # 获取指标
        metrics = metrics_collector.get_metrics(target)

        if not metrics:
            self.send_response(503)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Failed to retrieve metrics")
            return

        # 生成响应
        self.send_response(200)
        self.send_header('Content-type', 'text/plain; version=0.0.4')
        self.end_headers()

        try:
            response = self.generate_prometheus_metrics(metrics)
            self.wfile.write(response.encode())
        except Exception as e:
            logger.error(f"Error generating metrics response: {str(e)}")
            metrics_collector.increment_error_counter()
            error_response = "# ERROR: Failed to generate metrics"
            self.wfile.write(error_response.encode())

    def handle_health_check(self):
        """处理健康检查"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK")

    def handle_self_metrics(self, metrics_collector):
        """暴露exporter自身指标"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain; version=0.0.4')
        self.end_headers()

        with metrics_collector.lock:
            response_lines = [
                "# HELP php_exporter_requests_total Total requests handled by the exporter",
                "# TYPE php_exporter_requests_total counter",
                f"php_exporter_requests_total {metrics_collector.request_counter}",
                "# HELP php_exporter_errors_total Total errors encountered by the exporter",
                "# TYPE php_exporter_errors_total counter",
                f"php_exporter_errors_total {metrics_collector.error_counter}",
                "# HELP php_exporter_cache_size Current size of the metrics cache",
                "# TYPE php_exporter_cache_size gauge",
                f"php_exporter_cache_size {len(metrics_collector.metrics_cache)}"
            ]

        self.wfile.write("\n".join(response_lines).encode())

    def generate_prometheus_metrics(self, metrics):
        """生成Prometheus格式的指标"""
        output = []

        # 添加指标状态
        output.append("# HELP php_fpm_up Status of the PHP-FPM scrape")
        output.append("# TYPE php_fpm_up gauge")
        output.append(f"php_fpm_up{{target=\"{metrics['target']}\"}} 1")

        # 添加池信息
        if 'pool' in metrics:
            output.append("# HELP php_fpm_pool_info Information about the PHP-FPM pool")
            output.append("# TYPE php_fpm_pool_info gauge")
            output.append(
                f"php_fpm_pool_info{{target=\"{metrics['target']}\",pool=\"{metrics['pool']}\",process_manager=\"{metrics.get('process_manager', 'unknown')}\"}} 1")

        # 添加采集时间戳
        output.append("# HELP php_fpm_scrape_timestamp Timestamp of the last successful scrape")
        output.append("# TYPE php_fpm_scrape_timestamp gauge")
        output.append(f"php_fpm_scrape_timestamp{{target=\"{metrics['target']}\"}} {metrics['scrape_timestamp']}")

        # 添加更多指标
        for metric_name, metric_value in metrics.items():
            if isinstance(metric_value, (int, float)):
                # 跳过非指标字段
                if metric_name in ['target', 'pool', 'process_manager', 'scrape_timestamp']:
                    continue

                # 添加指标帮助信息
                metric_help = metric_name.replace('_', ' ').title()
                output.append(f"# HELP php_fpm_{metric_name} {metric_help}")
                output.append(f"# TYPE php_fpm_{metric_name} gauge")
                output.append(f"php_fpm_{metric_name}{{target=\"{metrics['target']}\"}} {metric_value}")

        return "\n".join(output)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """多线程HTTP服务器"""
    daemon_threads = True


def main():
    # 加载配置
    config_loader = ConfigLoader()
    try:
        config = config_loader.load_config()
    except Exception as e:
        logger.error(f"Failed to load configuration: {str(e)}")
        sys.exit(1)

    # 创建指标收集器
    metrics_collector = PhpFpmMetrics(config)

    # 启动HTTP服务器
    server_address = ('0.0.0.0', config['listen_port'])
    HandlerClass = PhpFpmMetricsHandler.create(metrics_collector, config)
    server = ThreadingHTTPServer(server_address, HandlerClass)

    logger.info(f"Starting PHP-FPM exporter on port {config['listen_port']}")
    logger.info(f"Scrape endpoint: /probe?target=<url>")
    logger.info(f"Health check endpoint: /health")
    logger.info(f"Self metrics endpoint: /metrics")
    logger.warning("WARNING: Target validation is disabled. This may expose SSRF vulnerabilities!")

    # 设置信号处理
    def shutdown(signum, frame):
        logger.info("Received shutdown signal")
        metrics_collector.stop()
        server.shutdown()
        server.server_close()
        logger.info("Server stopped")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == '__main__':
    main()
