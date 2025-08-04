公司老的业务都使用的是php语言写的，并且部署在K8s集群中，想通过不修改基础镜像的形式对业务的php-status进行监控。
在githup上搜索的了几个php_export都需要将export服务和php程序同时部署到一个镜像中，对我不太适应。
于是让AI 按照 blackbox_exporter 的形式编写了一个类型的python脚本，自己做了一些简单的修改。
原理就是运行 main.py脚本，暴露出8899端口
编辑prometheus配置文件，添加需要监控的域名、自定义labels、export_ip地址。
有类型需求的可以自行下载修改适配自己的业务。
# prometheus配置
  - job_name: '业务1'
    metrics_path: /probe
    static_configs:
      - targets:
        - 'https://域名1/php-status'
        labels:
          program: 自定义程序名称1
      - targets:
        - 'https://域名2/php-status'
        labels:
          program: 自定义程序名称2


    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: export_IP地址:8899

          
