 
### 特性说明
  - 冲定向
    - 规则
      - 规则1 
        http://192.168.101.2/av_scan
        直接获取post的包体. 
        或者提供一个页面post body内容.
      - 规则2
        将http://192.168.101.2/av_redirect/www.sohu.com/tag/55770冲定向到server http://www.sohu.com/tag/55770
        或者将http://192.168.101.2/av_redreict?uri=www.sohu.com/tag/55770重定向.
        
    - 目的
      > 熟悉url重写.  
  - 支持https.
  - 文档压缩.
    - 通过proxy_set_header Accept-encoding ""; 来设置不支持压缩.
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
    - nginx线程池的概念.
    - 
    
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
### 项目过程中遇到的问题
  - body filter中，buffer可以被hold起来，但是只能copy chain,而不能把参数in直接hold.
  - proxy 在需要较大的缓存时，必须采用如下命令设置较大的buffer, 否则每个链接的默认buffer只有8k，超过8k则不会继续从server下载.
    ```
              proxy_buffers 40960 4k;
            proxy_busy_buffers_size 100m;
    ```
  - Vary: Accept-Encoding
    - 这个字段是用来指示cdn缓存服务器，需要存几分拷贝.
  - content-lenght
    - chunk模式下可能没有.
    - 短链接, connection: close 时，可以没有.
    - 其他情况必须要有.
  - 如果有子链接，那么所有链接的charset/Accept-encoding 如果不一致，可能会导致内容读取出现问题.
    - 这就需要response-header延迟发送.
      - 一般情况下，如果一个链接有subrequest/upstream, 他们解析完响应就会被立即发送到客户端。 
        - 发送顺序如下:
          - 发送header
          - header_filter  ===> 将header发送出去.
          - body_filter.   ===> 将body发送出去. 
          - ngx_http_post_subrequest_t->handler. 
      - 如果subrequest在创建的时候设置了NGX_HTTP_SUBREQUEST_IN_MEMORY.
        - 注意upstream_buffer不能设置太小，否则upstream缓存不够.
        - subrequest的header会缓存起来,需要自己在ngx_http_post_subrequest_handler里手动发送.
        
        
  - subrequest似乎只能请求本地链接？
    - 是的. 

