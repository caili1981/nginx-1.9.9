### 待学习
  - nginx的配置手册
    > [配置手册](http://shouce.jb51.net/nginx/left.html)
  - upstream
  - subrequest
    - ngx_http_upstream_init_round_robin
  - cookie
  - SSI是什么.
  - SSL是如何支持的.
  - gzip模块.
  - chunk模块.
  - 能否撰写流模式的反病毒引擎？是否有开源的反病毒程序？
  - nginx实战一书.
  - tnginx
    - sysgurad模块. 据说这个模块在真实server的情况下很有用.
  - nginx跟踪调试
    [获取链接](https://www.cnblogs.com/jimodetiantang/p/9188789.html)
  - nginx如何保证sub request的顺序.
  - nginx header_filter/body_filter设计原理.
  - proxy_pass DNS如何获得?
  - [nginx从入门到精通](https://www.kancloud.cn/kancloud/master-nginx-develop/51833)
  - nginx stream模块.
  - [网易云课堂里](https://study.163.com/course/introduction.htm?courseId=1005083015#/courseDetail?tab=1)
  - nginx文件操作. 
    aio 机制.
  - nginx-copy filter.
  - nginx应用场景.
    https://docs.nginx.com/nginx/admin-guide/

### 主要特性
  - 与apache相比
    > apache一个进程处理一个连接. 每个进程不停的停止，以等待所需资源得到满足.
    > nginx采用事件处理模型，一个进程处理多个http连接.   
      > 时延，并发，性能都得到有效的提升.   
      > 每个事务都不能掉用阻塞函数，否则其他事务将无法得到调用，增加编程的难度.    
  - 全进程工作模式
    - 1 master & 多个worker
    - 为什么module里会有init_thread这个函数指针???
  - 全异步工作方式
    - 通过epoll等异步方式进行操作, 非常高效. 
    - 如果不小心掉用了阻塞操作，将会极大的影响nginx的性能.
### 模块
  - 定义
    - module
      - ctx
      - commands 
      - init_master
      - init_process
      - init_module
    
### 配置
  - 格式
    > 命令行 + 参数(可以多个).  
    > 每一个关键字都是一个命令, 如http/server/location都有对应的命令. 
    > 可以自定义命令。  
  - 匹配顺序
    - 正则表达式优先.
      - 正则表达式之间配置顺序优先
      - 如果匹配两个正则表达式，则第一个正则表达式生效. 
    - 如果没有匹配正则表达式，则用普通表达式.
      - 普通表达式按最长匹配优先.
  - 配置执行顺序
    - create_config
    - command_handler
    - init_config
  - 继承结构
    > 参见《深入理解nginx》第10章.
    
  - 注意问题:
    - flag的值一定要初始化成-1，否则会报错.
    - merge_loc_conf函数一定要写, 否则会出现配置不对的现象.
    - complex_value的str，不一定是以\0结尾. 
    
### nginx启动/处理流程
  - 读配置.
  - 建立监听端口.
    - ngx_http_add_listening
      - 设置handler处理函数 ngx_http_init_connection
    - ngx_open_listening_sockets
      - create & bind socket
    - ngx_configure_listening_sockets
      - 设置接收/发送buffer的大小.
      - 设置keepalive
      - listen socket
    - 启动子进程
      - ngx_epoll_add_event
        > 将accept事件挂载到事件列表中.
    - ngx_process_events_and_timers
      - ngx_epoll_process_events
        - ngx_event_accept
          - ngx_http_init_connection
            > 初始化连接，并设置read event的handler是 ngx_http_wait_request_handler
        - read事件
          - ngx_http_wait_request_handler
            - 创建ngx_http_request_t.
            - 将read event的handler设置为ngx_http_process_request_line.
            - ngx_http_process_request_line.
              - ngx_http_parse_request_line
                > 将read event设置为 ngx_http_process_request_headers
                - ngx_http_process_request_headers
                  - ngx_http_process_request
                    - ngx_http_handler
                      - ngx_http_core_run_phases
                        - ngx_http_core_content_phase
         
### nginx filter模块
  - body filter 和header filter是在产生响应后，并在发回client之前. 
    - 调用关系
      - ngx_http_static_handler
        - ngx_http_send_header
          - ngx_http_top_header_filter
        - ngx_http_output_filter
          - ngx_http_top_body_filter
            > 在一个请求过程中，这个函数可能会被调用很多次，如果所有的chain都没有置'last'标志，则后续仍会调用body_filter.
      - 由此可见，top_body_filter是在handler处理完之后被调用.
    - 和upstream的关系
      - upstream在调用完input_filter之后，会调用ngx_event_pipe_write_to_downstream, 并调用ngx_http_output_filter
      - 对于有upstream的时候，input_filter在前. ngx_http_top_body_filter调用在后.
    > 例如： 转发时若需要修改报文头content_length，则需要在header filter里进行.  
    > 如果要对报文进行改变，则应该在body filter里进行.    
    > body filter 会传入ngx_chain_t。 指向待输出的buffer.    
    > header filter 会传入ngx_http_request_t. 如果需要修改content length, 则需要在headers_out里进行修改.
  - upstream模块同样需要配置一个input filter. 这个filter在报文头已经收到并解析，但是报文体还在接收时.
    > 参见ngx_http_proxy_module.c
  - filter模块注册必须放在模块post_configuration回调函数里
    - 因为ngx_http_top_header_filter是在post_configuration里初始化的.
    - 如果放在command/preconfiguration里，初始化不起作用.
  - filter类型
    - header_filter
      - header/body_filter的顺序是和ngx_modules里注册顺序相反的.
      - ngx_http_top_header_filter(ngx_http_send_header函数内调用)
      - ngx_http_not_modified_header_filter
      - ngx_http_headers_filter 
        > 注意后面有一个header_filter
      - ngx_http_userid_filter
      - ngx_http_charset_header_filter
      - ngx_http_ssi_header_filter
      - ngx_http_gzip_header_filter
      - ngx_http_range_header_filter
      - ngx_http_chunked_header_filter
      - ngx_http_header_filter
        > 注意前面有一个ngx_http_headers_filter
        > ngx_http_write_filter将报文写出去. 

    - body_filter
      - ngx_http_top_body_filter (ngx_http_output_filter函数内调用)
      - ngx_http_range_body_filter
      - ngx_http_copy_filter
      - ngx_http_charset_body_filter
      - ngx_http_ssi_body_filter
      - ngx_http_postpone_filter
      - ngx_http_gzip_body_filter
      - ngx_http_chunked_body_filter
      - ngx_http_write_filter

### upstream 处理流程
  - 负载均衡
    - 加权round_robin
      > [算法链接](https://blog.csdn.net/zhangskd/article/details/50194069) ***非常经典***
    - least_conn
      > 最少连接的server优先.
    - ip_hash
      - 算法思路
        - 计算所有ip_server的权重之和.
        - 根据源ip，计算hash = hash(int)% total_weight.
        - 遍历所有的peer，如果hash> weight, 则，hash=hash-weight. 直到找到一个weight大于hash的peer为止.
      - 可以将同一个台主机绑定到同一台服务器上. 
        > 如果client是nat模式，而且源ip由可能变，则这种方式会出现问题. 应对方式是cookie_hash
    - url_hash
      - 根据url进行hash，相同的url会映射到同一个server上, 能搞提高server的缓存利用率.
    - cookie_hash
      - 根据cookie hash到不同的server上。由于一个用户的用户id cookie在一段时间内保持恒定. 根据cookie hash可以将用户绑定到特定的服务器上. 
    - fair
      - 根据每个请求的处理速度计算, 比加权轮询更加智能.
      
  - ngx_http_proxy_handler
    - ngx_http_upstream_create
    - ngx_http_read_client_request_body
      - ngx_http_upstream_init.    ====> upstream的启动函数, 进入它之后，所有的后续流程都将自动化进行，用户模块可以无需关心.
        - ngx_http_upstream_init_request
          - uscf->peer.init
            - ngx_http_upstream_init_ip_hash_peer
          - ngx_http_upstream_connect
            - ngx_event_connect_peer
              > r->upstream.peer.get 获得正确的peer地址.
            - ngx_http_upstream_send_request
              - ngx_http_upstream_send_request_body
              - ngx_http_upstream_process_header
                - ngx_http_upstream_process_body_in_memory
  - 从上述代码中可以看出，upstream设计的就是一层套一层的流水线模式. 初始化报文头, 发送报文，处理报文头，处理报文体. 
  - 每一级函数都可以被socket中断. 当socket的条件得以满足时会继续后续流程. 
  
### subrequest 处理流程.
  - subrequest被整合成一个树状结构.
  - 发送subrequest是按作树的后序遍历. 例如:
    > sub11->sub12->sub21->sub22
  - ngx_http_next_body_filter
    - 这个函数会在后序链表(ngx_http_postpone_filter)里会将自身添加到r->postponed队列.
    - 在它之前调用ngx_http_subrequest会排在当前request之前.
    - 在它之后调用的会排在之后.

### nginx事件
  - nginx 是事件驱动型设计，无阻塞模型.
  - 容器式编程(类似于面向对象的继承), 支持:
    - epoll
      - ngx_connect_t 里包含read和write事件队列
    - poll
    - select
  - nginx在如何将http的流程接上，费了很大的功夫，相关的代码也晦涩难懂.
    - r->connection->read/write->handler会指定当前状态的回调函数，从这个函数进去之后，会继续一个http的后续流程. 
      > 例如ngx_http_request_handler 函数. 
    

    
### HTTP 处理
  - 快速索引
    - server
      > 通配hash算法
    - location
      > 平衡二叉树.
  - http请求处理的11个阶段
    - 定义在ngx_http_core_main_conf_t里. 
    - 在http_module ctx定义的post 函数里，可以添加自己的处理函数.
      ```
      ngx_http_handler_pt *h;
      ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
      h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
      if (h == NULL) {
          return NGX_ERROR;
      }
      *h = ngx_http_hello_world_post_read_phase_handler;
      ```
### upstream
  - 相关命令
    - proxy_pass
    - proxy_redirect
    - proxy_store
    - proxy_bind
  - upstream的三种处理方式
    - 不转发上游响应.
      - subrequest可能要用到，因为我们需要修改上游响应.
    - 上游网速快
    - 下游网速快
  - proxy_pass
    - ngx_http_proxy_pass
      > 读取配置信息，并改变ngx_http_core_module的处理函数. 
    - ngx_http_proxy_handler
      - ngx_http_upstream_create, 
      - 设立upstream相关的回调函数.
        - create_request
        - process_header
        - abort/reinit request
        - finalize_request
        - input_filter
  
    - ngx_http_read_client_request_body
      > 读取整个请求报文.
      - 最后调用ngx_http_upstream_init
        - create_request callback
          > proxy 模块，create request就是创建/修改相应的http请求.   
          > 例如: 正常http1.1连接的connection时keep-alive的，但是proxy要求，connection需要改成close. 这是rfc的规定.
        - ngx_http_upstream_connect
          - 设置回调
            ```
            c->write->handler = ngx_http_upstream_handler;
            c->read->handler = ngx_http_upstream_handler;

            u->write_event_handler = ngx_http_upstream_send_request_handler;
            u->read_event_handler = ngx_http_upstream_process_header;
            ```
            - 通过这个回调的设定，下次当有upstream的响应到达时，系统就可以正确的恢复执行.
            - nginx的所有现场恢复都是通过这四个回调函数进行的.
            - write/read是大的阶段。write_event_handler/read_event_handler是小的阶段.
            - 注意write_event_handler是upstream的.
          - ngx_http_upstream_send_request
            - ngx_http_upstream_process_header
   - proxy_cache
    - [nginx的cache机制](https://blog.csdn.net/weiyuefei/article/details/35295117)
    - 将proxy到的内容cache到本地, 如果下次代理同样的uri，就直接从cache里去内容。
      - proxy_cache 打开时会启动两个cache管理的进程. 
      - cache manager process和nginx worker process共享内存. 
      - 如果需要打开一个新的文件，worker会将一个cache描述符加入到共享内存里. 
      - cache manger 会读取这个描述符队列, 并将这个描述符中所对应的buf chain写到文件里.
      - 由于cache manager的存在，worker process不会再进行文件的读写操作，相关文件交由cache manager去完成. 
        - worker thread只往共享队列里添加描述符. 性能非常高.
        - proxy cache和open_file_cache不一样. 
          - 静态文件默认情况下是由sendfile交由内存完成发送.
          - 再gzip打开的时候，会通过pread读取, 注意这个操作是阻塞的. 所有一般都需要为静态文件配置缓存，以提高性能. 

      ```
      nobody    1920  0.0  0.0  34780  2720 ?        S    18:21   0:00 nginx: cache manager process
      nobody    1921  0.0  0.0  34780  2720 ?        S    18:21   0:00 nginx: cache loader process
      ```
      - 多个worker-thread之间会以共享内存的方式访问cache.
    - 实例:
      ```
        proxy_cache_path /usr/local/nginx/html/cache levels=1:2 keys_zone=cache_one:1m inactive=1d max_size=30g;
        location ~ ^/av_redirect/(.*)/(.*)$ {
            resolver 172.29.151.60;

            #proxy_pass和proxy_cache必须在同级目录下
            proxy_pass http://$1/$2;
            proxy_cache_key $host$uri$args;
            proxy_cache cache_one;
            proxy_cache_valid 200 1d;
            proxy_cache_valid any 1m;
        }

      ```

### sub request
  - 相关函数
    - ngx_http_subrequest
      > 创建一个链接，此时并没有将请求发出去.
      - ngx_http_post_request
    - ngx_http_send_special
    - ngx_http_run_posted_requests
    
    
### 数据结构
  - nginx hash
    - ngx_hash_t 
      - 不同与普通的hash表，它是一开始就知道了元素的key.
        > 普通的hash表是无法使用这种结构的. 
      - 不是以链表的形式，而是以内存块偏移的形式进行组织.
        - 所有bucket都指向同一片内存（偏移不同).
        - 通过连续内存，提高性能.
        
    - ngx_hash_combined_t 
      - 支持前/后通配符匹配. 实际上是查找三次.   
        - 精确匹配  
        - 前通配符匹配.
        - 后通配符匹配.
      - server的查找使用的是这种方式.
      
  - nginx 内存池
    - ngx_pool_t
    - 将多次的malloc汇聚成一次大片的malloc
      - 优点
        - 从而减少malloc的次数，
        - 减少内存碎片，提高整体性能.
        - 避免内存泄漏. 
      - 缺点
        - 内存浪费，是一种以空间换时间的做法.
      - 适用范围
        - 在一个生命周期内，如处理一个http请求时，中间会有多次内存的申请的情况, 能极大提升效率.
        - 如果在生命周期内，可以提前释放的部分，最好不用memory pool的方式. 
        - 不定长度的申请，能极大程度的减少内存碎片.
        - 非常适用于容易产生内存泄漏的地方. 
    - 和objcache比较.
      - objcache比较适用于定长的申请和释放, memory pool适用于不定长的申请.
      - memory pool更使用于一个生命周期(如session)内都存在的内存段, objcache更适用于短期使用的. 
      
### nginx phase handler
  - phase handler定义了处理报文的几个步骤
  - ngx_http_handler
    - ngx_http_core_generic_phase 0
      - 默认没有挂载
    - ngx_http_core_rewrite_phase 1 
      - ngx_http_rewrite_handler
    - ngx_http_core_find_config_phase 2
    - ngx_http_core_rewrite_phase 3 
      - ngx_http_rewrite_handler
    - ngx_http_core_post_rewrite_phase 4 
    - ngx_http_core_generic_phase 5
      - ngx_http_limit_req_handler
    - ngx_http_core_generic_phase 6 
      - ngx_http_limit_conn_handler 
    - ngx_http_core_access_phase 7
      - ngx_http_access_handler
    - ngx_http_core_access_phase 8
      - ngx_http_auth_basic_handler
    - ngx_http_core_post_access_phase 9
      - 暂时没有挂载
    - ngx_http_core_content_phase 10 
      > 如果r->content_handler, 则不会调用后续的phase handler. 这意味着content_handler & phase_handler只有一个能生效. 
      - ngx_http_index_handler
    - ngx_http_core_content_phase 11
      - ngx_http_autoindex_handler
    - ngx_http_autoindex_handler 12
      - ngx_http_static_handler
        - ngx_http_send_header
        - ngx_http_output_filter
  ```
  (gdb) p *ph
  $23 = {checker = 0x42a51c <ngx_http_core_generic_phase>, handler = 0x46d069   <ngx_http_hello_world_post_read_phase_handler>, next = 1}
  (gdb) p ph[0].checker
  $24 = (ngx_http_phase_handler_pt) 0x42a51c <ngx_http_core_generic_phase>
  (gdb) p ph[1].checker
  $25 = (ngx_http_phase_handler_pt) 0x42a584 <ngx_http_core_rewrite_phase>
  (gdb) p ph[1]
  $26 = {checker = 0x42a584 <ngx_http_core_rewrite_phase>, handler = 0x45a6f3 <ngx_http_rewrite_handler>, next = 2}
  (gdb) p ph[2]
  $27 = {checker = 0x42aa0f <ngx_http_core_find_config_phase>, handler = 0x0, next = 0}
  (gdb) p ph[3]
  $28 = {checker = 0x42a584 <ngx_http_core_rewrite_phase>, handler = 0x45a6f3 <ngx_http_rewrite_handler>, next = 4}
  (gdb) p ph[4]
  $29 = {checker = 0x42a5bf <ngx_http_core_post_rewrite_phase>, handler = 0x0, next = 2}
  (gdb) p ph[5]
  $30 = {checker = 0x42a51c <ngx_http_core_generic_phase>, handler = 0x455f85 <ngx_http_limit_req_handler>, next = 7}
  (gdb) p ph[6]
  $31 = {checker = 0x42a51c <ngx_http_core_generic_phase>, handler = 0x4554ac <ngx_http_limit_conn_handler>, next = 7}
  (gdb) p ph[7]
  $32 = {checker = 0x42a676 <ngx_http_core_access_phase>, handler = 0x454aa9 <ngx_http_access_handler>, next = 10}
  (gdb) p ph[8]
  $33 = {checker = 0x42a676 <ngx_http_core_access_phase>, handler = 0x4544d8 <ngx_http_auth_basic_handler>, next = 10}
  (gdb) p ph[9]
  $34 = {checker = 0x42a77c <ngx_http_core_post_access_phase>, handler = 0x0, next = 10}
  (gdb) p ph[10]
  $35 = {checker = 0x42b488 <ngx_http_core_content_phase>, handler = 0x445275 <ngx_http_index_handler>, next = 13}
  (gdb) p ph[11]
  $36 = {checker = 0x42b488 <ngx_http_core_content_phase>, handler = 0x452fd8 <ngx_http_autoindex_handler>, next = 13}
  (gdb) p ph[12]
  $37 = {checker = 0x42b488 <ngx_http_core_content_phase>, handler = 0x444a5a <ngx_http_static_handler>, next = 13}
  (gdb) p ph[13]
  $38 = {checker = 0x0, handler = 0x50000002, next = 0}
  (gdb)
  ```
  

### ngxin 脚本引擎和变量
  - nginx 脚本兼容pcre.
    - perl.
    - 支持正则表达式.
    - rewrite 只能能直接对url进行重写.
      - 模式匹配
        - ~ 表示对uri进行模式匹配.
        - (.+?) 表示贪婪查找.
        - (.*)表示非贪婪查找结果.
        - 
        ```
             location /av_download {
            resolver 172.29.151.60;
            set $a "args is: $args\n";

            if ($arg_target ~ ^(.+?)/(.*)$) {
                set $b "非贪婪查找结果:$2\n";
            }

            if ($arg_target ~ ^(.*)/(.*)$) {
                set $c "贪婪查找结果:$2\n";
            }
            echo "\n$a\n$b\n$c\n";            
        }
        curl http://192.168.101.2/av_download?target=www.sohu.com/a/b/279837212_260616?_f=index_chan08news_6

        args is: target=www.sohu.com/a/b/279837212_260616?_f=index_chan08news_6

        非贪婪查找结果:a/b/279837212_260616?_f=index_chan08news_6

        贪婪查找结果:279837212_260616?_f=index_chan08news_6
        ```
  - nginx内部的脚本也是通过command来实现的.
    - set $file "index.html" 
      - 解析这个配置的时候，就会通过"ngx_http_rewrite_set"来进行处理。处理流程如下:
        - 检查变量字段是不是以$开头
        - 将变量加入到cmcf->variables_keys中, 而且是changable的. 
          - 为什么要放入main的配置中, 而不是loc的配置中??? 
            > 因为变量的定义是整个main结构所见的.
          > 为什么需要添加？？不应该是在模块的preconfiguration中就已经添加了变量么？？？
          > 如果没有经过set 语句，就不会加入到variables_keys中，后续使用就会报错.
        - 获取变量的下标.
        - 根据loc的配置，执行相应的script. 
    - 系统会将一行脚本编译成ngx_http_script_value_code_t’存入ngx_http_rewrite_loc_conf_t->codes中. 
      - 脚本由一系列字符串组成, 可以分成多个执行块（执行块不定长）.
        - 每个执行块都以函数指针开头.
        - 后续跟执行此函数需要的变量.
        - 每次进入函数指针所指的函数时，会将codes的当前位置进行偏移, 便宜的大小由当前函数所对应的数据结构决定. 

          ```
          set $user_name jack;
          set $key_not_found abcd
          ```
          > 上述一段代码，最终rewrite模块编译出的codes如下:
            ```
            (gdb) p *(ngx_http_script_value_code_t *)((char *)rlcf->codes->elts)
            $58 = {code = 0x442850 <ngx_http_script_value_code>, value = 0, text_len = 4, text_data = 7201071}
            (gdb) p sizeof(ngx_http_script_value_code_t)
            $59 = 32
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+32)
            $60 = (ngx_http_script_code_pt) 0x4429ae <ngx_http_script_var_set_handler_code>
            (gdb) p sizeof(ngx_http_script_var_handler_code_t)
            $61 = 24
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+24)
            $62 = (ngx_http_script_code_pt) 0x6de12f
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+24+32)
            $63 = (ngx_http_script_code_pt) 0x442850 <ngx_http_script_value_code>
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+32+24+32)
            $64 = (ngx_http_script_code_pt) 0x4428bb <ngx_http_script_set_var_code>
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+32+24+32+24)
            $65 = (ngx_http_script_code_pt) 0x0
            ```

  - 内部变量
    - 模块内部已经定义的变量. 
      > 通过ngx_http_variables_t所定义的.
    
    ```
    在nginx.conf中
    if ($http_user_agent ~ MIME) {
      rewrite ^(.*)$ /mise/$1 break;
    }
    ```
  - 外部变量
    - 用户自己定义的变量
      > set语句所定义的.
    ```
    ```
  - 特殊变量
    - $arg_xxx/$cookie_xxx
      > 如: $arg_class表示url问号后所代表的参数.
      > 它其实也是一个变量，在cmcf里占一个位置。它的处理程序就是读取url，并把相应的变量解析出来， 性能不如正常的变量.
  - 变量共享
    > 变量的生命周期，同一个主请求内.
    > 需要特别注意的是，如果两个location下对同一个变量赋值，而且会出现跳转，或者子请求到另一个location时，变量就会被覆盖。
  - 相应步骤:
    - 所有可能用到的变量都在preconfiguration里添加到main_conf->variables_keys里.
    - 读取配置的时候，如果遇到相应的变量，则从main_conf->variables_keys里查找，是否存在.
      > 脚本 set 所对应的操作，会用到ngx_http_variables_t->set_handler函数，如果这个值将会更改，则需要定义相应的set_handler.
      > NGX_HTTP_REWRITE_PHASE的回调函数ngx_http_rewrite_handler会触发脚本的执行.  
    - 在所需要的阶段赋值, 配置阶段或者连接处理阶段都可以.
  - ngx_http_variables_add_core_vars
  - ngx_http_variables_t
    > 所有变量，都通过variables进行定义
  - ngx_variables_value_t
  - ngx_http_complex_value
    > 这个函数可以获得复杂脚本表达式的值. ngx_http_set_complex_value_slot可以进行读取脚本表达式.
  - 执行顺序
    ```
      set $file index1.html;
      index $file;
      set $file index2.html;
    ```
    - 上述配置会最终重定向到indext2.html. 
      - rewrite phase
        - 步骤1. file=index1.html.
        - 步骤2. file=index2.html.
      - content phase
        - 步骤1. 冲定向到file, 结果显示index2.html.
    
### nginx 文件操作.
  - 
### 调用栈
  ```
  (gdb) bt
  #0  ngx_http_hello_world_handler (r=0x6b0120) at ./src/ext/ngx_http_hello_world_module/ngx_http_hello_world_module.c:56
  #1  0x000000000042b467 in ngx_http_core_content_phase (r=0x6b0120, ph=<optimized out>) at src/http/ngx_http_core_module.c:1363
  #2  0x00000000004263d0 in ngx_http_core_run_phases (r=r@entry=0x6b0120) at src/http/ngx_http_core_module.c:840
  #3  0x00000000004264e9 in ngx_http_handler (r=r@entry=0x6b0120) at src/http/ngx_http_core_module.c:823
  #4  0x000000000042e30d in ngx_http_process_request (r=r@entry=0x6b0120) at src/http/ngx_http_request.c:1911
  #5  0x000000000043041a in ngx_http_process_request_headers (rev=rev@entry=0x6c3ec0) at src/http/ngx_http_request.c:1342
  #6  0x00000000004306e7 in ngx_http_process_request_line (rev=rev@entry=0x6c3ec0) at src/http/ngx_http_request.c:1022
  #7  0x0000000000430e05 in ngx_http_wait_request_handler (rev=0x6c3ec0) at src/http/ngx_http_request.c:499
  #8  0x00000000004232a6 in ngx_epoll_process_events (cycle=<optimized out>, timer=<optimized out>, flags=<optimized out>)
      at src/event/modules/ngx_epoll_module.c:822
  #9  0x000000000041b8d4 in ngx_process_events_and_timers (cycle=cycle@entry=0x6b2920) at src/event/ngx_event.c:242
  #10 0x0000000000421437 in ngx_worker_process_cycle (cycle=cycle@entry=0x6b2920, data=data@entry=0x0) at src/os/unix/ngx_process_cycle.c:753
  #11 0x000000000041fed6 in ngx_spawn_process (cycle=cycle@entry=0x6b2920, proc=proc@entry=0x4213b6 <ngx_worker_process_cycle>, data=data@entry=0x0,
      name=name@entry=0x4711f6 "worker process", respawn=respawn@entry=-4) at src/os/unix/ngx_process.c:198
  #12 0x000000000042159f in ngx_start_worker_processes (cycle=cycle@entry=0x6b2920, n=1, type=type@entry=-4) at src/os/unix/ngx_process_cycle.c:358
  #13 0x0000000000422495 in ngx_master_process_cycle (cycle=0x6b2920, cycle@entry=0x6ae910) at src/os/unix/ngx_process_cycle.c:243
  #14 0x0000000000404458 in main (argc=<optimized out>, argv=<optimized out>) at src/core/nginx.c:359
  (gdb)
  ```
