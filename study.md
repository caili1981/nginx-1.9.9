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
  
### 配置
  - 格式
    > 命令行 + 参数(可以多个).  
    > 每一个关键字都是一个命令, 如http/server/location都有对应的命令. 
    > 可以自定义命令。  
  - 继承结构
    > 参见《深入理解nginx》第10章.
    
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

            
    
    
### nginx事件
  - nginx 是事件驱动型设计，无阻塞模型.
  - 容器式编程(类似于面向对象的继承), 支持:
    - epoll
      - ngx_connect_t 里包含read和write事件队列
    - poll
    - select

    
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
  - proxy_pass
    - ngx_http_proxy_pass
      > 读取配置信息，并改变ngx_http_core_module的处理函数. 
    - ngx_http_proxy_handler
      > ngx_http_upstream_create, 并设立upstream相关的回调函数.
    - ngx_http_read_client_request_body
      > 读取整个请求报文.
      - 最后掉用ngx_http_upstream_init
        - ngx_http_upstream_connect
          - ngx_http_upstream_send_request
            - ngx_http_upstream_process_header

        
    
### 数据结构
  - nginx hash
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
