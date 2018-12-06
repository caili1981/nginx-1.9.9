 
### 特性说明
  - 冲定向
    - 规则
      - 规则1 
        - 获取post包体的真实地址.
        - 将post命令转换成get命令.
        - 在resp里回应下载并过滤之后的文件.
      - 规则2
        将http://192.168.101.2/av/www.sohu.com/tag/55770冲定向到server http://www.sohu.com/tag/55770
    - 目的
      > 熟悉url重写.      
  - 病毒扫描
    - 规则
      - 将所有的resp文件全部发送到目的av_server上. 并且以load-balance的形式进行. 
      - 扫描出结果之后
        - 发现病毒
          > 将扫描结果返回. 必须依照自定义的message格式进行相应.
        - 未发现病毒
          > 返回原始页面.
  - 所用到的模块
    - upstream. 
      > 重写server名字.
    - subrequest.
      - 与av server通信.
      - AV server也采用nginx-server的方式, 不过以阻塞模式进行, 并且存成文件. 
        > 主要是熟悉nginx的异步文件操作.
        > AV server的响应模块以文本方式返回. 
    - av-server之间load-balance
    - yara的实现.
    
### 配置
  - config
    ```
    upstream backend_av_server {
      server 127.0.0.1;
    }
    av_server backend_av_server:
    location /av/ {
      proxy_pass http://$url/;
      if ($http_method == "get") {
        av_content resp;
        av_msg "Warning: found virus in file<$filename>, size<$http_content_length> time cost:${av_time_cost}s";
      }
      
      if ($http_method == "post") {
        av req;
      }
    }
    ```
