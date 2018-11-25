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
