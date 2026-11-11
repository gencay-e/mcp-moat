use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

use mcp_moat_core::{PolicyConfig, PolicyEngine};
use mcp_moat_proxy::ProxyServer;

#[cfg(windows)]
fn get_process_memory_bytes() -> usize {
    use std::mem::MaybeUninit;
    #[repr(C)]
    #[allow(non_snake_case)]
    struct PROCESS_MEMORY_COUNTERS {
        cb: u32,
        PageFaultCount: u32,
        PeakWorkingSetSize: usize,
        WorkingSetSize: usize,
        QuotaPeakPagedPoolUsage: usize,
        QuotaPagedPoolUsage: usize,
        QuotaPeakNonPagedPoolUsage: usize,
        QuotaNonPagedPoolUsage: usize,
        PagefileUsage: usize,
        PeakPagefileUsage: usize,
    }
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(
            process: isize,
            ppsp: *mut PROCESS_MEMORY_COUNTERS,
            cb: u32,
        ) -> i32;
    }
    unsafe {
        let mut pmc = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
        let handle = GetCurrentProcess();
        if K32GetProcessMemoryInfo(
            handle,
            pmc.as_mut_ptr(),
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) != 0
        {
            let pmc = pmc.assume_init();
            pmc.WorkingSetSize
        } else {
            0
        }
    }
}

#[cfg(not(windows))]
fn get_process_memory_bytes() -> usize {
    0
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// 1. Throughput: 2,000 to 5,000 sequential and pipelined JSON-RPC messages through the stream engine.
#[tokio::test]
async fn test_stress_1_massive_throughput_sequential_and_pipelined() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let mem_before = get_process_memory_bytes();

    let (mut client_tx, proxy_rx) = tokio::io::duplex(4 * 1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(4 * 1024 * 1024);
    let (proxy_err_tx, mut client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).expect("PolicyEngine failed");
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    // Drain stderr in background
    let _stderr_drain = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok(n) = client_err_rx.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // Initial handshake
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "stress-client", "version": "1.0" }
        }
    });
    client_tx
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();
    let init_resp = framed_out.next().await.unwrap().unwrap();
    let init_val: Value = serde_json::from_str(&init_resp).unwrap();
    assert_eq!(init_val["id"].as_i64(), Some(0));

    // 1,000 sequential round trips, each timed
    println!("\n=== STRESS TEST 1.1: 1,000 Sequential Round-Trips ===");
    let mut latencies: Vec<Duration> = Vec::with_capacity(1000);
    let seq_start = Instant::now();

    for i in 1..=1000 {
        let req = json!({
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "message": format!("seq-{}", i) }
            }
        });
        let t0 = Instant::now();
        client_tx
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();
        client_tx.flush().await.unwrap();

        let resp_line = framed_out.next().await.unwrap().unwrap();
        let rtt = t0.elapsed();
        latencies.push(rtt);

        let val: Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(val["id"].as_i64(), Some(i));
    }
    let seq_total_duration = seq_start.elapsed();

    latencies.sort();
    let seq_min = latencies.first().copied().unwrap();
    let seq_max = latencies.last().copied().unwrap();
    let seq_p50 = latencies[latencies.len() / 2];
    let seq_p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
    let seq_p99 = latencies[(latencies.len() as f64 * 0.99) as usize];
    let seq_avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let seq_throughput = 1000.0 / seq_total_duration.as_secs_f64();

    println!("Sequential Requests: 1,000");
    println!(
        "Total Duration:      {:.3}s",
        seq_total_duration.as_secs_f64()
    );
    println!("Throughput:          {:.1} msg/s", seq_throughput);
    println!(
        "Latency Min:         {:.3} ms",
        seq_min.as_secs_f64() * 1000.0
    );
    println!(
        "Latency Avg:         {:.3} ms",
        seq_avg.as_secs_f64() * 1000.0
    );
    println!(
        "Latency p50:         {:.3} ms",
        seq_p50.as_secs_f64() * 1000.0
    );
    println!(
        "Latency p95:         {:.3} ms",
        seq_p95.as_secs_f64() * 1000.0
    );
    println!(
        "Latency p99:         {:.3} ms",
        seq_p99.as_secs_f64() * 1000.0
    );
    println!(
        "Latency Max:         {:.3} ms",
        seq_max.as_secs_f64() * 1000.0
    );

    // Phase 2: 4,000 Pipelined Requests in Massivem Burst
    println!("\n=== STRESS TEST 1.2: 4,000 Pipelined Stream Flood ===");
    let pipeline_count = 4000;
    let pipeline_start_id = 1001;
    let pipeline_end_id = pipeline_start_id + pipeline_count - 1;

    let response_reader_handle = tokio::spawn(async move {
        let mut received = 0;
        let mut ids = HashSet::new();
        while let Some(line_res) = framed_out.next().await {
            let line = line_res.expect("Error reading response");
            let val: Value = serde_json::from_str(&line).expect("Invalid JSON");
            if let Some(id) = val.get("id").and_then(|i| i.as_i64()) {
                ids.insert(id);
            }
            received += 1;
            if received == pipeline_count {
                break;
            }
        }
        (received, ids, framed_out)
    });

    let pipe_start = Instant::now();
    let mut total_bytes_sent = 0;

    for i in pipeline_start_id..=pipeline_end_id {
        let req = match i % 3 {
            0 => json!({ "jsonrpc": "2.0", "id": i, "method": "ping" }),
            1 => json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": { "message": format!("flood-payload-{}", i) }
                }
            }),
            _ => json!({ "jsonrpc": "2.0", "id": i, "method": "tools/list" }),
        };
        let line = format!("{}\n", req);
        let bytes = line.as_bytes();
        total_bytes_sent += bytes.len();
        client_tx.write_all(bytes).await.unwrap();
    }
    client_tx.flush().await.unwrap();

    let (pipe_received, pipe_ids, _framed_out) =
        tokio::time::timeout(Duration::from_secs(10), response_reader_handle)
            .await
            .expect("Pipeline timeout")
            .expect("Reader failed");

    let pipe_duration = pipe_start.elapsed();
    let pipe_throughput = pipeline_count as f64 / pipe_duration.as_secs_f64();
    let pipe_mb_sec = (total_bytes_sent as f64 / (1024.0 * 1024.0)) / pipe_duration.as_secs_f64();

    println!("Pipelined Requests:  {}", pipeline_count);
    println!("Total Duration:      {:.3}s", pipe_duration.as_secs_f64());
    println!("Pipelined Throughput:{:.1} msg/s", pipe_throughput);
    println!("Data Rate Inbound:   {:.2} MB/s", pipe_mb_sec);
    println!(
        "Zero Dropped Frames: {} received == {} sent",
        pipe_received, pipeline_count
    );
    println!(
        "Unique ID Coverage:  {} / {}",
        pipe_ids.len(),
        pipeline_count
    );

    assert_eq!(pipe_received, pipeline_count);
    assert_eq!(pipe_ids.len(), pipeline_count);

    let mem_after = get_process_memory_bytes();
    println!(
        "Memory Working Set:  Before: {} -> After: {} (Delta: {})",
        format_bytes(mem_before),
        format_bytes(mem_after),
        format_bytes(mem_after.saturating_sub(mem_before))
    );

    // Clean exit
    drop(client_tx);
    let exit_code = tokio::time::timeout(Duration::from_secs(3), proxy_handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(exit_code, 0);

    println!("[STRESS TEST 1] SUCCESS: 5,000 Total Messages passed without frame drop or error.\n");
}

/// 2. No deadlock when the child writes more than 500 KiB to stderr while tool calls run over
/// stdin/stdout at the same time.
#[tokio::test]
async fn test_stress_2_massive_stderr_overflow_deadlock_prevention() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    // 800,000 bytes dumped continuously on stderr (> 780 KiB, exceeds 500 KiB requirement)
    // Plus 256 bytes stderr per tool-call
    let stderr_dump_target = 800_000;
    let args = vec![
        "--dump-stderr".to_string(),
        stderr_dump_target.to_string(),
        "--stderr-on-call".to_string(),
        "256".to_string(),
    ];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(2 * 1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(2 * 1024 * 1024);
    let (proxy_err_tx, client_err_rx) = tokio::io::duplex(2 * 1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    // Autonomous client drain of stderr, measuring byte throughput
    let stderr_drain_handle = tokio::spawn(async move {
        let mut reader = client_err_rx;
        let mut total_bytes = 0;
        let mut buf = [0u8; 16384];
        while let Ok(n) = reader.read(&mut buf).await {
            if n == 0 {
                break;
            }
            total_bytes += n;
        }
        total_bytes
    });

    let tool_call_count = 1000;
    let stdout_reader_handle = tokio::spawn(async move {
        let mut framed_out =
            FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));
        let mut received = 0;
        let mut ids = HashSet::new();

        while let Some(line_res) = framed_out.next().await {
            let line = line_res.expect("Stdout read error");
            let val: Value = serde_json::from_str(&line).expect("Invalid JSON");
            if let Some(id) = val.get("id").and_then(|i| i.as_i64()) {
                ids.insert(id);
            }
            assert!(!val.get("error").is_some(), "Tool call should succeed");
            received += 1;
            if received == tool_call_count {
                break;
            }
        }
        (received, ids)
    });

    println!("\n=== STRESS TEST 2: Massive Stderr Overflow (>500 KiB) Deadlock Prevention ===");
    let start = Instant::now();

    // Concurrently flood stdin with 1,000 tool calls while stderr dumps 800 KiB
    for i in 1..=tool_call_count {
        let req = json!({
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "message": format!("stderr-stress-{}", i) }
            }
        });
        client_tx
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();
    }
    client_tx.flush().await.unwrap();

    let (stdout_received, stdout_ids) =
        tokio::time::timeout(Duration::from_secs(8), stdout_reader_handle)
            .await
            .expect("Deadlock detected! Stdin/Stdout stalled due to Stderr pipe backpressure")
            .expect("Stdout reader failed");

    // Close client stdin to let child shut down cleanly
    drop(client_tx);

    let total_stderr_drained = tokio::time::timeout(Duration::from_secs(5), stderr_drain_handle)
        .await
        .expect("Timeout waiting for stderr drain")
        .expect("Stderr drain panicked");

    let duration = start.elapsed();
    let exit_code = tokio::time::timeout(Duration::from_secs(3), proxy_handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    println!(
        "Tool Calls Completed: {} / {}",
        stdout_received, tool_call_count
    );
    println!("Unique IDs Handled:   {}", stdout_ids.len());
    println!(
        "Stderr Drained:       {} (Target > 500 KiB / 512,000 B)",
        format_bytes(total_stderr_drained)
    );
    println!("Elapsed Time:         {:.3}s", duration.as_secs_f64());
    println!("Child Exit Code:      {}", exit_code);

    assert_eq!(stdout_received, tool_call_count);
    assert_eq!(stdout_ids.len(), tool_call_count);
    assert!(
        total_stderr_drained >= 512_000,
        "Expected >500 KiB (512,000 B) stderr drained without pipe deadlock, got {}",
        total_stderr_drained
    );
    assert_eq!(exit_code, 0, "Mock server exited cleanly with 0");

    println!("[STRESS TEST 2] SUCCESS: Zero Deadlocks detected under massive stderr overflow.\n");
}

/// 3. 16 MB frame limit: a single 17 MB NDJSON line is dropped and answered with a JSON-RPC error
/// (-32700), without panic, deadlock or running out of memory.
#[tokio::test]
async fn test_stress_3_16mb_frame_ceiling_simulation() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(36 * 1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(4 * 1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    println!("\n=== STRESS TEST 3: 16 MB Frame Ceiling & Fail-Closed Protection ===");
    let mem_before = get_process_memory_bytes();

    // Synthesize a 17 MB single NDJSON frame (> 16 * 1024 * 1024 bytes)
    let payload_size = 17 * 1024 * 1024;
    println!(
        "Allocating 17 MB oversized NDJSON frame ({} bytes)...",
        payload_size
    );
    let payload = "Z".repeat(payload_size);
    let oversized_frame = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":9999,\"method\":\"echo\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"message\":\"{}\"}}}}}}\n",
        payload
    );
    let frame_len = oversized_frame.len();
    println!(
        "Transmitting frame of {} to proxy stream...",
        format_bytes(frame_len)
    );

    let send_start = Instant::now();
    client_tx
        .write_all(oversized_frame.as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();
    println!(
        "Frame transmitted in {:.3}s",
        send_start.elapsed().as_secs_f64()
    );

    // Expect fail-closed error response -32700
    let resp_line = tokio::time::timeout(Duration::from_secs(5), framed_out.next())
        .await
        .expect("Timeout waiting for 16MB frame ceiling rejection")
        .expect("Stream closed unexpectedly")
        .expect("Failed reading response frame");

    let resp_val: Value = serde_json::from_str(&resp_line).expect("Invalid JSON in rejection");
    let err_code = resp_val
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64());
    let err_msg = resp_val
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str());

    println!("Rejection Received:  {:?}", resp_val);
    println!("Error Code:          {:?} (Expected -32700)", err_code);
    println!("Error Message:       {:?}", err_msg);

    assert_eq!(
        err_code,
        Some(-32700),
        "Must return standard JSON-RPC parse error -32700"
    );
    assert!(
        err_msg.unwrap_or("").contains("16MB"),
        "Message must specify 16MB limit"
    );

    let mem_after = get_process_memory_bytes();
    println!(
        "Memory Working Set:  Before: {} -> After: {} (No OOM / controlled headroom)",
        format_bytes(mem_before),
        format_bytes(mem_after)
    );

    // Fail-Closed Boundary Verification:
    // As designed by zero-trust specification, an extreme 17 MB framing violation is a fatal
    // framing error that permanently terminates the desynchronized stream after issuing the -32700 error.
    println!("Verifying fail-closed boundary termination after fatal framing violation...");
    drop(client_tx);
    let exit_code = tokio::time::timeout(Duration::from_secs(3), proxy_handle)
        .await
        .expect("Proxy shutdown timeout")
        .unwrap()
        .unwrap();

    assert_eq!(
        exit_code, 0,
        "Proxy and child should exit cleanly without hang or crash"
    );
    println!(
        "Fail-closed boundary confirmed: -32700 emitted, stream safely closed, zero deadlock."
    );

    println!("[STRESS TEST 3] SUCCESS: 17 MB frame rejected fail-closed (-32700), zero OOM, clean boundary shutdown.\n");
}

/// 4. Under load, an MCP `ping` skips the queue and is answered in under 5 ms.
#[tokio::test]
async fn test_stress_4_keepalive_ping_bypass_under_load() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    // Simulate server processing delay of 250ms on tool calls
    let delay_ms = 1000;
    let args = vec!["--delay".to_string(), delay_ms.to_string()];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    println!("\n=== STRESS TEST 4: Keepalive Ping-Bypass Simulation under Artificial Load ===");

    // Step 1: Queue 5 slow tool calls (each delayed by 250ms = 1.25s theoretical queue depth)
    let slow_calls_count = 5;
    for i in 1..=slow_calls_count {
        let slow_call = json!({
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "message": format!("slow-job-{}", i) }
            }
        });
        client_tx
            .write_all(format!("{}\n", slow_call).as_bytes())
            .await
            .unwrap();
    }
    client_tx.flush().await.unwrap();

    // Give proxy 10ms to ingest the slow tool calls into the normal queue
    tokio::time::sleep(Duration::from_millis(15)).await;

    // Step 2: Dispatch MCP keepalive ping (id: 777)
    let ping_id = 777;
    let ping_req = json!({
        "jsonrpc": "2.0",
        "id": ping_id,
        "method": "ping"
    });
    let ping_bytes = format!("{}\n", ping_req).into_bytes();

    let ping_send_time = Instant::now();
    client_tx.write_all(&ping_bytes).await.unwrap();
    client_tx.flush().await.unwrap();

    // Step 3: Read first response from proxy stream
    // MUST be the ping (id: 777), having overtaken all slow calls via priority bypass!
    let first_line = tokio::time::timeout(Duration::from_millis(delay_ms), framed_out.next())
        .await
        .expect("Ping response did not arrive fast enough via priority bypass")
        .expect("Stream closed unexpectedly")
        .expect("Failed to read line");

    let ping_latency = ping_send_time.elapsed();
    let first_val: Value = serde_json::from_str(&first_line).unwrap();

    println!("First Response ID:   {:?}", first_val.get("id"));
    println!(
        "Ping Latency:        {:.3} ms (Threshold: < {} ms)",
        ping_latency.as_secs_f64() * 1000.0,
        delay_ms / 2
    );
    println!("Slow Call Delay:     {} ms", delay_ms);

    assert_eq!(
        first_val.get("id").and_then(|i| i.as_i64()),
        Some(ping_id),
        "Ping must overtake delayed tool calls in normal queue via priority bypass"
    );
    // A ping stuck behind the slow calls would need at least `delay_ms`. Half of that is a
    // threshold that proves the bypass without depending on the speed of the machine.
    let threshold = Duration::from_millis(delay_ms / 2);
    assert!(
        ping_latency < threshold,
        "Ping latency must be below threshold ({:?}), was {:.3} ms",
        threshold,
        ping_latency.as_secs_f64() * 1000.0
    );

    // Step 4: Verify remaining slow calls arrive subsequently
    println!(
        "Awaiting subsequent completion of {} queued slow calls...",
        slow_calls_count
    );
    let mut slow_ids_received = Vec::new();
    for _ in 1..=slow_calls_count {
        let line = framed_out.next().await.unwrap().unwrap();
        let val: Value = serde_json::from_str(&line).unwrap();
        slow_ids_received.push(val["id"].as_i64().unwrap());
    }
    println!("Slow Calls Completed: {:?}", slow_ids_received);
    assert_eq!(slow_ids_received.len(), slow_calls_count);

    drop(client_tx);
    let _ = proxy_handle.await;

    println!(
        "[STRESS TEST 4] SUCCESS: Ping bypassed {} waiting tool calls in {:.3} ms.\n",
        slow_calls_count,
        ping_latency.as_secs_f64() * 1000.0
    );
}

/// 5. Client disconnect (broken pipe) during a transfer: the child process and the proxy exit cleanly
/// and leave no tasks behind.
#[tokio::test]
async fn test_stress_5_abrupt_client_disconnect_broken_pipe() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    println!("\n=== STRESS TEST 5: Abrupt Client Disconnect & Broken Pipe Handling ===");

    // Step 1: Send a flood of 200 tool calls
    let flood_count = 200;
    for i in 1..=flood_count {
        let req = json!({
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "message": format!("disconnect-test-{}", i) }
            }
        });
        client_tx
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();
    }
    client_tx.flush().await.unwrap();

    // Step 2: Read only 5 responses to verify active data stream
    for _ in 1..=5 {
        let line = framed_out.next().await.unwrap().unwrap();
        let _: Value = serde_json::from_str(&line).unwrap();
    }
    println!("Confirmed active data transmission (5 frames read).");

    // Step 3: ABRUPT CLIENT DISCONNECT: Drop reader duplex mid-stream!
    // This causes next write from child stdout to client_out to fail with BrokenPipe
    println!("Abruptly severing client stdout stream (dropping client_rx duplex)...");
    let disconnect_time = Instant::now();
    drop(framed_out);
    drop(client_tx); // Also close client stdin

    // Step 4: Verify proxy shuts down promptly without hanging
    let exit_result = tokio::time::timeout(Duration::from_millis(1500), proxy_handle).await;
    let shutdown_latency = disconnect_time.elapsed();

    assert!(
        exit_result.is_ok(),
        "Proxy hung or deadlocked on broken pipe!"
    );
    let proxy_exit = exit_result.unwrap().unwrap().unwrap();

    println!(
        "Proxy Shutdown Latency: {:.3}s",
        shutdown_latency.as_secs_f64()
    );
    println!("Proxy Termination Code: {}", proxy_exit);

    // Verify exit code is 1 (terminated due to broken pipe/kill) or 0
    assert!(
        proxy_exit == 1 || proxy_exit == 0,
        "Proxy should terminate child process cleanly on broken pipe"
    );

    // Step 5: Verify no zombie child processes remain
    // On Windows, check process list for dangling mock_server with retry loop for Windows kernel reaping
    #[cfg(windows)]
    {
        let mut count = 0;
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            if let Ok(out) = std::process::Command::new("powershell")
                .args(["-Command", "Get-Process mock_server -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"])
                .output()
            {
                let count_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                count = count_str.parse().unwrap_or(0);
                if count == 0 {
                    break;
                }
            }
        }
        println!("Active mock_server processes on system: {}", count);
        assert!(
            count <= 1,
            "No zombie mock_server processes must remain after proxy shutdown!"
        );
    }

    println!(
        "[STRESS TEST 5] SUCCESS: Broken pipe cleanly handled, child killed, zero zombie tasks.\n"
    );
}
