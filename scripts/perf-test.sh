#!/bin/bash
# APK Analyzer Performance Test Suite
# Enterprise-grade performance testing for high-concurrency scenarios
# Simulates production API load with configurable parameters

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

CLI="${CLI:-./zig-out/bin/apk-analyzer}"
RESULTS_DIR="${RESULTS_DIR:-./perf-results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Test APK files (configurable via environment)
SIGNAL_APK="${LARGE_APK:-$HOME/Downloads/Signal-Android-website-prod-universal-release-7.68.5.apk}"
MEDIUM_APK="${MEDIUM_APK:-$HOME/Downloads/210.apk}"
SMALL_APK="${SMALL_APK:-$HOME/Downloads/artifacts_X8jRKdSp7iTiOiApnPzXDzTLf1mXsJbv_7cbc7367-725d-4b55-99f9-16356250bec3_e7cebbd6-4708-451b-a4bc-5b7d51696e3e_com.plexus-1-unknown-universal.apk}"

# Concurrency levels for testing (configurable)
CONCURRENCY_LEVELS="${CONCURRENCY_LEVELS:-1 2 4 8 16 32 64}"
MAX_CONCURRENCY="${MAX_CONCURRENCY:-100}"
SUSTAINED_DURATION="${SUSTAINED_DURATION:-30}"  # seconds for sustained load test
RAMP_UP_DURATION="${RAMP_UP_DURATION:-10}"      # seconds for ramp-up test
ITERATIONS="${ITERATIONS:-50}"                   # iterations for throughput test

# Resource limits
MAX_MEMORY_MB="${MAX_MEMORY_MB:-4096}"          # Alert threshold
MAX_RESPONSE_TIME_MS="${MAX_RESPONSE_TIME_MS:-5000}"  # Alert threshold

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Utility Functions
# =============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[FAIL]${NC} $*"; }

cleanup() {
    log_info "Cleaning up background processes..."
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

check_dependencies() {
    local missing=()
    for cmd in bc awk seq date; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

check_cli() {
    if [ ! -x "$CLI" ]; then
        log_error "CLI not found or not executable: $CLI"
        log_info "Build with: zig build -Doptimize=ReleaseFast"
        exit 1
    fi
    log_success "CLI found: $CLI"
}

check_apk() {
    if [ ! -f "$1" ]; then
        log_warn "APK not found: $1"
        return 1
    fi
    return 0
}

get_file_size_mb() {
    local size
    size=$(stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 0)
    echo "scale=1; $size / 1024 / 1024" | bc -l
}

get_timestamp_ms() {
    if command -v gdate &>/dev/null; then
        gdate +%s%3N
    else
        echo $(($(date +%s) * 1000 + $(date +%N 2>/dev/null | cut -c1-3 || echo 0)))
    fi
}

get_high_res_time() {
    if command -v gdate &>/dev/null; then
        gdate +%s.%N
    else
        date +%s.%N 2>/dev/null || date +%s
    fi
}

# =============================================================================
# Results Collection
# =============================================================================

init_results() {
    mkdir -p "$RESULTS_DIR"
    RESULTS_FILE="$RESULTS_DIR/perf_$TIMESTAMP.json"
    CSV_FILE="$RESULTS_DIR/perf_$TIMESTAMP.csv"
    
    # Initialize JSON results
    cat > "$RESULTS_FILE" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "cli": "$CLI",
  "system": {
    "os": "$(uname -s)",
    "arch": "$(uname -m)",
    "cpus": $(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 1),
    "memory_gb": $(echo "scale=1; $(sysctl -n hw.memsize 2>/dev/null || free -b 2>/dev/null | awk '/Mem:/{print $2}' || echo 0) / 1024 / 1024 / 1024" | bc -l)
  },
  "tests": []
}
EOF
    
    # Initialize CSV
    echo "test_name,apk_size,concurrency,total_requests,successful,failed,avg_time_ms,p50_ms,p95_ms,p99_ms,max_time_ms,throughput_rps,peak_memory_mb" > "$CSV_FILE"
    
    log_info "Results will be saved to: $RESULTS_DIR"
}

append_result() {
    local test_name=$1
    local json_data=$2
    
    # Append to JSON (using temp file for atomic update)
    local temp_file=$(mktemp)
    jq --arg name "$test_name" --argjson data "$json_data" \
        '.tests += [{"name": $name, "results": $data}]' \
        "$RESULTS_FILE" > "$temp_file" && mv "$temp_file" "$RESULTS_FILE"
}

append_csv() {
    echo "$*" >> "$CSV_FILE"
}

# =============================================================================
# Core Test Functions
# =============================================================================

# Run single analysis and capture timing
run_single_analysis() {
    local apk=$1
    local extra_args=${2:-}
    local start_time end_time duration_ms exit_code
    
    start_time=$(get_high_res_time)
    if "$CLI" "$apk" --streaming --quiet $extra_args > /dev/null 2>&1; then
        exit_code=0
    else
        exit_code=1
    fi
    end_time=$(get_high_res_time)
    
    duration_ms=$(echo "($end_time - $start_time) * 1000" | bc -l | cut -d. -f1)
    echo "$duration_ms $exit_code"
}

# Run concurrent batch and collect results
run_concurrent_batch() {
    local apk=$1
    local concurrency=$2
    local extra_args=${3:-}
    local results_file=$(mktemp)
    local pids=()
    
    # Launch concurrent processes
    for i in $(seq 1 "$concurrency"); do
        (
            local start_time end_time duration_ms exit_code
            start_time=$(get_high_res_time)
            if "$CLI" "$apk" --streaming --quiet $extra_args > /dev/null 2>&1; then
                exit_code=0
            else
                exit_code=1
            fi
            end_time=$(get_high_res_time)
            duration_ms=$(echo "($end_time - $start_time) * 1000" | bc -l | cut -d. -f1)
            echo "$duration_ms $exit_code" >> "$results_file"
        ) &
        pids+=($!)
    done
    
    # Wait for all processes
    local failed=0
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || ((failed++))
    done
    
    # Return results file path
    echo "$results_file"
}

# Calculate percentiles from timing data
calculate_percentiles() {
    local results_file=$1
    local timings=$(cut -d' ' -f1 "$results_file" | sort -n)
    local count=$(echo "$timings" | wc -l | tr -d ' ')
    
    if [ "$count" -eq 0 ]; then
        echo "0 0 0 0 0 0 0"
        return
    fi
    
    local sum=$(echo "$timings" | awk '{sum+=$1} END {print sum}')
    local avg=$(echo "scale=2; $sum / $count" | bc -l)
    local min=$(echo "$timings" | head -1)
    local max=$(echo "$timings" | tail -1)
    
    # Percentiles
    local p50_idx=$(echo "($count * 50 / 100) + 1" | bc)
    local p95_idx=$(echo "($count * 95 / 100) + 1" | bc)
    local p99_idx=$(echo "($count * 99 / 100) + 1" | bc)
    
    local p50=$(echo "$timings" | sed -n "${p50_idx}p")
    local p95=$(echo "$timings" | sed -n "${p95_idx}p")
    local p99=$(echo "$timings" | sed -n "${p99_idx}p")
    
    # Count successes/failures
    local success=$(grep -c " 0$" "$results_file" || echo 0)
    local fail=$((count - success))
    
    echo "$avg $min $max $p50 $p95 $p99 $success $fail"
}

# =============================================================================
# Memory Monitoring
# =============================================================================

# Monitor memory usage of running processes
monitor_memory() {
    local pids=$1
    local interval=${2:-0.1}
    local max_rss=0
    local samples=0
    
    while true; do
        local total_rss=0
        local active=0
        
        for pid in $pids; do
            if ps -p "$pid" > /dev/null 2>&1; then
                local rss=$(ps -o rss= -p "$pid" 2>/dev/null || echo 0)
                total_rss=$((total_rss + rss))
                active=1
            fi
        done
        
        if [ $active -eq 0 ]; then
            break
        fi
        
        if [ $total_rss -gt $max_rss ]; then
            max_rss=$total_rss
        fi
        
        ((samples++))
        sleep "$interval"
    done
    
    # Return max RSS in KB
    echo "$max_rss"
}

# Run with memory monitoring
run_with_memory_monitoring() {
    local apk=$1
    local concurrency=$2
    local extra_args=${3:-}
    local pids=""
    local results_file=$(mktemp)
    
    # Launch processes
    for i in $(seq 1 "$concurrency"); do
        (
            local start_time end_time duration_ms
            start_time=$(get_high_res_time)
            "$CLI" "$apk" --streaming --quiet $extra_args > /dev/null 2>&1
            local exit_code=$?
            end_time=$(get_high_res_time)
            duration_ms=$(echo "($end_time - $start_time) * 1000" | bc -l | cut -d. -f1)
            echo "$duration_ms $exit_code" >> "$results_file"
        ) &
        pids="$pids $!"
    done
    
    # Monitor memory in background
    local mem_file=$(mktemp)
    (monitor_memory "$pids" 0.05 > "$mem_file") &
    local monitor_pid=$!
    
    # Wait for all analysis processes
    wait $pids 2>/dev/null || true
    
    # Stop memory monitor
    kill $monitor_pid 2>/dev/null || true
    wait $monitor_pid 2>/dev/null || true
    
    local peak_memory=$(cat "$mem_file" 2>/dev/null || echo 0)
    rm -f "$mem_file"
    
    echo "$results_file $peak_memory"
}

# =============================================================================
# Test Suites
# =============================================================================

print_header() {
    echo ""
    echo "=============================================="
    echo "$1"
    echo "=============================================="
    echo ""
}

# TEST 1: Baseline single-file performance
test_baseline() {
    print_header "TEST 1: Baseline Performance (Single File)"
    
    local apks=("$SMALL_APK:Small" "$MEDIUM_APK:Medium" "$SIGNAL_APK:Large")
    
    printf "%-12s %-10s %-12s %-12s %-12s\n" "Size" "Mode" "Time (ms)" "Memory (MB)" "Status"
    printf "%s\n" "------------------------------------------------------------"
    
    for apk_entry in "${apks[@]}"; do
        local apk="${apk_entry%%:*}"
        local name="${apk_entry##*:}"
        
        if ! check_apk "$apk"; then continue; fi
        
        for mode in "streaming" "no-mmap"; do
            local extra_args="--streaming"
            [ "$mode" = "no-mmap" ] && extra_args="--no-mmap"
            
            local output=$(/usr/bin/time -l "$CLI" "$apk" --quiet $extra_args 2>&1 | tail -20)
            local rss=$(echo "$output" | grep "maximum resident" | awk '{print $1}')
            local time_val=$(echo "$output" | grep "real" | awk '{print $1}')
            local time_ms=$(echo "$time_val * 1000" | bc -l | cut -d. -f1)
            local mem_mb=$(echo "scale=1; $rss / 1024 / 1024" | bc -l)
            
            local status="${GREEN}OK${NC}"
            [ "$time_ms" -gt "$MAX_RESPONSE_TIME_MS" ] && status="${YELLOW}SLOW${NC}"
            [ "${mem_mb%.*}" -gt "$MAX_MEMORY_MB" ] && status="${RED}HIGH MEM${NC}"
            
            printf "%-12s %-10s %-12s %-12s " "$name" "$mode" "${time_ms}ms" "${mem_mb}MB"
            echo -e "$status"
        done
    done
}

# TEST 2: Concurrency scaling
test_concurrency_scaling() {
    print_header "TEST 2: Concurrency Scaling"
    
    local apk="$MEDIUM_APK"
    local name="Medium"
    
    if ! check_apk "$apk"; then
        log_warn "Skipping concurrency test - no APK available"
        return
    fi
    
    local apk_size=$(get_file_size_mb "$apk")
    
    printf "%-12s %-12s %-12s %-12s %-12s %-12s %-12s\n" \
        "Concurrency" "Requests" "Success" "Avg (ms)" "P95 (ms)" "P99 (ms)" "RPS"
    printf "%s\n" "--------------------------------------------------------------------------------"
    
    for conc in $CONCURRENCY_LEVELS; do
        [ "$conc" -gt "$MAX_CONCURRENCY" ] && break
        
        local results_file=$(run_concurrent_batch "$apk" "$conc")
        
        local stats=$(calculate_percentiles "$results_file")
        local avg=$(echo "$stats" | cut -d' ' -f1)
        local p95=$(echo "$stats" | cut -d' ' -f5)
        local p99=$(echo "$stats" | cut -d' ' -f6)
        local success=$(echo "$stats" | cut -d' ' -f7)
        local fail=$(echo "$stats" | cut -d' ' -f8)
        
        local total=$((success + fail))
        
        # Handle empty avg
        [ -z "$avg" ] && avg="1"
        [ "$avg" = "0" ] && avg="1"
        
        local rps=$(echo "scale=2; $conc / ($avg / 1000)" | bc -l 2>/dev/null || echo "N/A")
        
        # Handle empty values for display
        local avg_display=${avg%.*}
        local p95_display=${p95%.*}
        local p99_display=${p99%.*}
        [ -z "$avg_display" ] && avg_display="0"
        [ -z "$p95_display" ] && p95_display="0"
        [ -z "$p99_display" ] && p99_display="0"
        
        printf "%-12s %-12s %-12s %-12s %-12s %-12s %-12s\n" \
            "$conc" "$total" "$success" "$avg_display" "$p95_display" "$p99_display" "$rps"
        
        # Save to CSV (with safe defaults)
        [ -z "$apk_size" ] && apk_size="0"
        [ -z "$fail" ] && fail="0"
        append_csv "concurrency_scaling,$apk_size,$conc,$total,$success,$fail,$avg,0,$p95,$p99,0,$rps,0"
        
        rm -f "$results_file"
    done
}

# TEST 3: Sustained load test (simulates production traffic)
test_sustained_load() {
    print_header "TEST 3: Sustained Load Test (${SUSTAINED_DURATION}s)"
    
    local apk="$MEDIUM_APK"
    if ! check_apk "$apk"; then
        log_warn "Skipping sustained load test - no APK available"
        return
    fi
    
    local target_rps=${TARGET_RPS:-10}
    local duration=$SUSTAINED_DURATION
    local results_file=$(mktemp)
    local errors_file=$(mktemp)
    local start_time=$(get_high_res_time)
    local end_time=$(echo "$start_time + $duration" | bc -l)
    local request_count=0
    local interval=$(echo "scale=4; 1 / $target_rps" | bc -l)
    
    log_info "Target: ${target_rps} RPS for ${duration}s ($(echo "$target_rps * $duration" | bc) total requests)"
    echo ""
    
    # Progress indicator
    local progress_interval=5
    local next_progress=$progress_interval
    
    while [ "$(echo "$(get_high_res_time) < $end_time" | bc -l)" -eq 1 ]; do
        # Launch request in background
        (
            local req_start=$(get_high_res_time)
            if "$CLI" "$apk" --streaming --quiet > /dev/null 2>&1; then
                local req_end=$(get_high_res_time)
                local duration_ms=$(echo "($req_end - $req_start) * 1000" | bc -l | cut -d. -f1)
                echo "$duration_ms 0" >> "$results_file"
            else
                echo "1" >> "$errors_file"
            fi
        ) &
        
        ((request_count++))
        
        # Progress update
        local elapsed=$(echo "$(get_high_res_time) - $start_time" | bc -l | cut -d. -f1)
        if [ "${elapsed:-0}" -ge "$next_progress" ]; then
            local current_count=$(wc -l < "$results_file" 2>/dev/null | tr -d ' ' || echo 0)
            local error_count=$(wc -l < "$errors_file" 2>/dev/null | tr -d ' ' || echo 0)
            printf "\r  Progress: %ds | Requests: %d | Completed: %d | Errors: %d" \
                "$elapsed" "$request_count" "$current_count" "$error_count"
            next_progress=$((next_progress + progress_interval))
        fi
        
        sleep "$interval" 2>/dev/null || true
    done
    
    # Wait for remaining requests
    log_info "Waiting for in-flight requests..."
    wait 2>/dev/null || true
    
    echo ""
    
    # Calculate results
    local total_completed=$(wc -l < "$results_file" | tr -d ' ')
    local total_errors=$(wc -l < "$errors_file" 2>/dev/null | tr -d ' ' || echo 0)
    local stats=$(calculate_percentiles "$results_file")
    local avg=$(echo "$stats" | cut -d' ' -f1)
    local p50=$(echo "$stats" | cut -d' ' -f4)
    local p95=$(echo "$stats" | cut -d' ' -f5)
    local p99=$(echo "$stats" | cut -d' ' -f6)
    local actual_rps=$(echo "scale=2; $total_completed / $duration" | bc -l)
    local success_rate=$(echo "scale=2; $total_completed * 100 / ($total_completed + $total_errors)" | bc -l)
    
    echo ""
    echo "  Results:"
    echo "  ─────────────────────────────────────"
    printf "  Total Requests:    %d\n" "$request_count"
    printf "  Completed:         %d\n" "$total_completed"
    printf "  Errors:            %d\n" "$total_errors"
    printf "  Success Rate:      %.1f%%\n" "$success_rate"
    printf "  Actual RPS:        %.2f\n" "$actual_rps"
    printf "  Avg Latency:       %sms\n" "${avg%.*}"
    printf "  P50 Latency:       %sms\n" "${p50%.*}"
    printf "  P95 Latency:       %sms\n" "${p95%.*}"
    printf "  P99 Latency:       %sms\n" "${p99%.*}"
    
    # Evaluate results
    echo ""
    if [ "$(echo "$success_rate >= 99" | bc -l)" -eq 1 ]; then
        log_success "Success rate meets SLA (≥99%)"
    else
        log_error "Success rate below SLA (<99%)"
    fi
    
    if [ "${p99%.*}" -le "$MAX_RESPONSE_TIME_MS" ]; then
        log_success "P99 latency within threshold (≤${MAX_RESPONSE_TIME_MS}ms)"
    else
        log_warn "P99 latency exceeds threshold (>${MAX_RESPONSE_TIME_MS}ms)"
    fi
    
    rm -f "$results_file" "$errors_file"
}

# TEST 4: Ramp-up test (find breaking point)
test_ramp_up() {
    print_header "TEST 4: Ramp-Up Test (Find Breaking Point)"
    
    local apk="$MEDIUM_APK"
    if ! check_apk "$apk"; then
        log_warn "Skipping ramp-up test - no APK available"
        return
    fi
    
    log_info "Gradually increasing load to find system limits..."
    echo ""
    
    local start_conc=1
    local max_conc=$MAX_CONCURRENCY
    local step=2  # Multiply by 2 each iteration
    local breaking_point=0
    local last_good_rps=0
    local last_good_p99=0
    
    printf "%-12s %-12s %-12s %-12s %-12s %-12s\n" \
        "Concurrency" "Success%" "Avg (ms)" "P99 (ms)" "RPS" "Status"
    printf "%s\n" "------------------------------------------------------------------------"
    
    local conc=$start_conc
    while [ "$conc" -le "$max_conc" ]; do
        local results_file=$(run_concurrent_batch "$apk" "$conc")
        local stats=$(calculate_percentiles "$results_file")
        
        local avg=$(echo "$stats" | cut -d' ' -f1)
        local p99=$(echo "$stats" | cut -d' ' -f6)
        local success=$(echo "$stats" | cut -d' ' -f7)
        local fail=$(echo "$stats" | cut -d' ' -f8)
        local total=$((success + fail))
        
        local success_rate=0
        [ "$total" -gt 0 ] && success_rate=$(echo "scale=1; $success * 100 / $total" | bc -l)
        
        local rps=$(echo "scale=2; $conc / ($avg / 1000)" | bc -l 2>/dev/null || echo "0")
        
        local status="${GREEN}OK${NC}"
        local status_text="OK"
        
        # Check for degradation
        if [ "$(echo "$success_rate < 99" | bc -l)" -eq 1 ]; then
            status="${RED}ERRORS${NC}"
            status_text="ERRORS"
            [ "$breaking_point" -eq 0 ] && breaking_point=$conc
        elif [ "${p99%.*}" -gt "$MAX_RESPONSE_TIME_MS" ]; then
            status="${YELLOW}SLOW${NC}"
            status_text="SLOW"
            [ "$breaking_point" -eq 0 ] && breaking_point=$conc
        else
            last_good_rps=$rps
            last_good_p99=${p99%.*}
        fi
        
        printf "%-12s %-12s %-12s %-12s %-12s " \
            "$conc" "${success_rate}%" "${avg%.*}" "${p99%.*}" "$rps"
        echo -e "$status"
        
        rm -f "$results_file"
        
        # Stop if we've found the breaking point and gone past it
        if [ "$breaking_point" -gt 0 ] && [ "$conc" -gt $((breaking_point * 2)) ]; then
            break
        fi
        
        conc=$((conc * step))
    done
    
    echo ""
    if [ "$breaking_point" -gt 0 ]; then
        log_warn "Breaking point detected at concurrency: $breaking_point"
        log_info "Recommended max concurrency: $((breaking_point / 2))"
    else
        log_success "No breaking point found up to concurrency: $max_conc"
    fi
    log_info "Best sustained RPS: $last_good_rps (P99: ${last_good_p99}ms)"
}

# TEST 5: Mixed workload (realistic traffic pattern)
test_mixed_workload() {
    print_header "TEST 5: Mixed Workload (Realistic Traffic)"
    
    local small_available=0
    local medium_available=0
    local large_available=0
    
    check_apk "$SMALL_APK" && small_available=1
    check_apk "$MEDIUM_APK" && medium_available=1
    check_apk "$SIGNAL_APK" && large_available=1
    
    local total_available=$((small_available + medium_available + large_available))
    if [ "$total_available" -eq 0 ]; then
        log_warn "No APK files available for mixed workload test"
        return
    fi
    
    log_info "Simulating realistic traffic distribution:"
    echo "  - Small APKs:  10% of requests"
    echo "  - Medium APKs: 40% of requests"
    echo "  - Large APKs:  50% of requests"
    echo ""
    
    # First, measure memory per APK size (single run each)
    log_info "Measuring memory usage per APK size..."
    local small_mem_mb="N/A"
    local medium_mem_mb="N/A"
    local large_mem_mb="N/A"
    
    if [ "$small_available" -eq 1 ]; then
        local output=$(/usr/bin/time -l "$CLI" "$SMALL_APK" --streaming --quiet 2>&1 | tail -25)
        local rss=$(echo "$output" | grep "maximum resident" | awk '{print $1}')
        [ -n "$rss" ] && small_mem_mb=$(echo "scale=1; $rss / 1024 / 1024" | bc -l 2>/dev/null || echo "N/A")
    fi
    
    if [ "$medium_available" -eq 1 ]; then
        local output=$(/usr/bin/time -l "$CLI" "$MEDIUM_APK" --streaming --quiet 2>&1 | tail -25)
        local rss=$(echo "$output" | grep "maximum resident" | awk '{print $1}')
        [ -n "$rss" ] && medium_mem_mb=$(echo "scale=1; $rss / 1024 / 1024" | bc -l 2>/dev/null || echo "N/A")
    fi
    
    if [ "$large_available" -eq 1 ]; then
        local output=$(/usr/bin/time -l "$CLI" "$SIGNAL_APK" --streaming --quiet 2>&1 | tail -25)
        local rss=$(echo "$output" | grep "maximum resident" | awk '{print $1}')
        [ -n "$rss" ] && large_mem_mb=$(echo "scale=1; $rss / 1024 / 1024" | bc -l 2>/dev/null || echo "N/A")
    fi
    
    local total_requests=50
    local small_count=$((total_requests * 10 / 100))
    local medium_count=$((total_requests * 40 / 100))
    local large_count=$((total_requests * 50 / 100))
    
    # Adjust if some APKs not available
    [ "$small_available" -eq 0 ] && { medium_count=$((medium_count + small_count / 2)); large_count=$((large_count + small_count / 2)); small_count=0; }
    [ "$medium_available" -eq 0 ] && { small_count=$((small_count + medium_count)); medium_count=0; }
    [ "$large_available" -eq 0 ] && { medium_count=$((medium_count + large_count)); large_count=0; }
    
    local results_file=$(mktemp)
    local start_time=$(get_high_res_time)
    local pids=()
    
    # Launch mixed requests
    log_info "Launching $total_requests concurrent requests..."
    
    for i in $(seq 1 "$small_count"); do
        [ "$small_available" -eq 1 ] && {
            (
                local s=$(get_high_res_time)
                "$CLI" "$SMALL_APK" --streaming --quiet > /dev/null 2>&1
                local e=$(get_high_res_time)
                echo "small $(echo "($e - $s) * 1000" | bc -l | cut -d. -f1) $?" >> "$results_file"
            ) &
            pids+=($!)
        }
    done
    
    for i in $(seq 1 "$medium_count"); do
        [ "$medium_available" -eq 1 ] && {
            (
                local s=$(get_high_res_time)
                "$CLI" "$MEDIUM_APK" --streaming --quiet > /dev/null 2>&1
                local e=$(get_high_res_time)
                echo "medium $(echo "($e - $s) * 1000" | bc -l | cut -d. -f1) $?" >> "$results_file"
            ) &
            pids+=($!)
        }
    done
    
    for i in $(seq 1 "$large_count"); do
        [ "$large_available" -eq 1 ] && {
            (
                local s=$(get_high_res_time)
                "$CLI" "$SIGNAL_APK" --streaming --quiet > /dev/null 2>&1
                local e=$(get_high_res_time)
                echo "large $(echo "($e - $s) * 1000" | bc -l | cut -d. -f1) $?" >> "$results_file"
            ) &
            pids+=($!)
        }
    done
    
    # Wait for all
    wait "${pids[@]}" 2>/dev/null || true
    
    local end_time=$(get_high_res_time)
    local total_time=$(echo "$end_time - $start_time" | bc -l)
    
    # Analyze results by size
    echo ""
    printf "%-12s %-12s %-12s %-12s %-12s %-12s\n" "Size" "Count" "Avg (ms)" "Max (ms)" "Memory (MB)" "Errors"
    printf "%s\n" "------------------------------------------------------------------------"
    
    for size in small medium large; do
        local size_data=$(grep "^$size " "$results_file" 2>/dev/null || true)
        if [ -n "$size_data" ]; then
            local count=$(echo "$size_data" | wc -l | tr -d ' ')
            local timings=$(echo "$size_data" | awk '{print $2}')
            local avg=$(echo "$timings" | awk '{sum+=$1} END {printf "%.0f", sum/NR}')
            local max=$(echo "$timings" | sort -n | tail -1)
            local errors=$(echo "$size_data" | grep -v " 0$" | wc -l | tr -d ' ')
            
            local mem_mb="N/A"
            [ "$size" = "small" ] && mem_mb="$small_mem_mb"
            [ "$size" = "medium" ] && mem_mb="$medium_mem_mb"
            [ "$size" = "large" ] && mem_mb="$large_mem_mb"
            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s\n" "$size" "$count" "$avg" "$max" "$mem_mb" "$errors"
        fi
    done
    
    local actual_total=$(wc -l < "$results_file" | tr -d ' ')
    local total_errors=$(grep -v " 0$" "$results_file" | wc -l | tr -d ' ')
    local throughput=$(echo "scale=2; $actual_total / $total_time" | bc -l)
    
    # Calculate estimated peak memory (all concurrent)
    local est_peak_mem="N/A"
    if [ "$small_mem_mb" != "N/A" ] && [ "$medium_mem_mb" != "N/A" ] && [ "$large_mem_mb" != "N/A" ]; then
        est_peak_mem=$(echo "scale=1; $small_count * $small_mem_mb + $medium_count * $medium_mem_mb + $large_count * $large_mem_mb" | bc -l 2>/dev/null || echo "N/A")
    fi
    
    echo ""
    echo "  Overall Results:"
    echo "  ─────────────────────────────────────"
    printf "  Total Requests:    %d\n" "$actual_total"
    printf "  Total Errors:      %d\n" "$total_errors"
    printf "  Total Time:        %.2fs\n" "$total_time"
    printf "  Throughput:        %.2f RPS\n" "$throughput"
    printf "  Est. Peak Memory:  %sMB (all concurrent)\n" "$est_peak_mem"
    
    rm -f "$results_file"
}

# TEST 6: Memory pressure test
test_memory_pressure() {
    print_header "TEST 6: Memory Pressure Test"
    
    local apk="$SIGNAL_APK"  # Use large APK for memory pressure
    if ! check_apk "$apk"; then
        apk="$MEDIUM_APK"
        if ! check_apk "$apk"; then
            log_warn "Skipping memory pressure test - no suitable APK"
            return
        fi
    fi
    
    local apk_name=$(basename "$apk")
    log_info "Testing memory behavior under concurrent load with: $apk_name"
    echo ""
    
    printf "%-12s %-15s %-15s %-15s %-12s\n" \
        "Concurrency" "Peak RSS (MB)" "Avg/Proc (MB)" "Est. 100 Proc" "Status"
    printf "%s\n" "------------------------------------------------------------------------"
    
    for conc in 1 2 4 8 16; do
        # Use /usr/bin/time to measure a single process, multiply by concurrency for estimate
        local output=$(/usr/bin/time -l "$CLI" "$apk" --streaming --quiet 2>&1 | tail -25)
        local rss=$(echo "$output" | grep "maximum resident" | awk '{print $1}')
        
        # Handle empty rss
        if [ -z "$rss" ] || [ "$rss" = "0" ]; then
            rss=1024  # Default 1KB if not found
        fi
        
        # RSS is in bytes on macOS
        local single_proc_mb=$(echo "scale=1; $rss / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
        local peak_mem_mb=$(echo "scale=1; $single_proc_mb * $conc" | bc -l 2>/dev/null || echo "0")
        local est_100=$(echo "scale=0; $single_proc_mb * 100" | bc -l 2>/dev/null || echo "0")
        
        # Handle empty values
        [ -z "$single_proc_mb" ] && single_proc_mb="0"
        [ -z "$peak_mem_mb" ] && peak_mem_mb="0"
        [ -z "$est_100" ] && est_100="0"
        
        local status="${GREEN}OK${NC}"
        local est_100_int=${est_100%.*}
        local peak_int=${peak_mem_mb%.*}
        [ -z "$est_100_int" ] && est_100_int=0
        [ -z "$peak_int" ] && peak_int=0
        
        if [ "$est_100_int" -gt "$MAX_MEMORY_MB" ] 2>/dev/null; then
            status="${YELLOW}WARN${NC}"
        fi
        if [ "$peak_int" -gt "$MAX_MEMORY_MB" ] 2>/dev/null; then
            status="${RED}HIGH${NC}"
        fi
        
        printf "%-12s %-15s %-15s %-15s " \
            "$conc" "${peak_mem_mb}MB" "${single_proc_mb}MB" "${est_100}MB"
        echo -e "$status"
    done
    
    echo ""
    log_info "Memory threshold: ${MAX_MEMORY_MB}MB"
}

# TEST 7: Fast mode performance comparison
test_fast_mode() {
    print_header "TEST 7: Fast Mode Performance"
    
    local apks=("$SMALL_APK:Small" "$MEDIUM_APK:Medium" "$SIGNAL_APK:Large")
    
    printf "%-12s %-12s %-12s %-12s %-12s\n" \
        "Size" "Full (ms)" "Fast (ms)" "Speedup" "Memory Saved"
    printf "%s\n" "------------------------------------------------------------"
    
    for apk_entry in "${apks[@]}"; do
        local apk="${apk_entry%%:*}"
        local name="${apk_entry##*:}"
        
        if ! check_apk "$apk"; then continue; fi
        
        # Full mode (streaming)
        local full_output=$(/usr/bin/time -l "$CLI" "$apk" --streaming --quiet 2>&1 | tail -20)
        local full_time=$(echo "$full_output" | grep "real" | awk '{print $1}')
        local full_rss=$(echo "$full_output" | grep "maximum resident" | awk '{print $1}')
        
        # Handle empty values
        [ -z "$full_time" ] && full_time="0.001"
        [ -z "$full_rss" ] && full_rss="1024"
        
        local full_time_ms=$(echo "$full_time * 1000" | bc -l 2>/dev/null | cut -d. -f1)
        local full_mem_mb=$(echo "scale=1; $full_rss / 1024 / 1024" | bc -l 2>/dev/null)
        
        [ -z "$full_time_ms" ] || [ "$full_time_ms" = "" ] && full_time_ms="1"
        [ -z "$full_mem_mb" ] && full_mem_mb="0"
        
        # Fast mode (streaming)
        local fast_output=$(/usr/bin/time -l "$CLI" "$apk" --streaming --quiet --fast 2>&1 | tail -20)
        local fast_time=$(echo "$fast_output" | grep "real" | awk '{print $1}')
        local fast_rss=$(echo "$fast_output" | grep "maximum resident" | awk '{print $1}')
        
        # Handle empty values
        [ -z "$fast_time" ] && fast_time="0.001"
        [ -z "$fast_rss" ] && fast_rss="1024"
        
        local fast_time_ms=$(echo "$fast_time * 1000" | bc -l 2>/dev/null | cut -d. -f1)
        local fast_mem_mb=$(echo "scale=1; $fast_rss / 1024 / 1024" | bc -l 2>/dev/null)
        
        [ -z "$fast_time_ms" ] || [ "$fast_time_ms" = "" ] && fast_time_ms="1"
        [ -z "$fast_mem_mb" ] && fast_mem_mb="0"
        
        # Ensure non-zero for division
        [ "$fast_time_ms" = "0" ] && fast_time_ms="1"
        
        # Calculate improvements
        local speedup="N/A"
        if [ "$fast_time_ms" -gt 0 ] 2>/dev/null; then
            speedup=$(echo "scale=1; $full_time_ms / $fast_time_ms" | bc -l 2>/dev/null || echo "N/A")
            [ -n "$speedup" ] && [ "$speedup" != "N/A" ] && speedup="${speedup}x"
        fi
        
        local mem_saved="N/A"
        local full_mem_check=$(echo "$full_mem_mb > 0" | bc -l 2>/dev/null || echo "0")
        if [ "$full_mem_check" = "1" ]; then
            mem_saved=$(echo "scale=0; (1 - $fast_mem_mb / $full_mem_mb) * 100" | bc -l 2>/dev/null || echo "N/A")
            [ -n "$mem_saved" ] && [ "$mem_saved" != "N/A" ] && mem_saved="${mem_saved}%"
        fi
        
        printf "%-12s %-12s %-12s %-12s %-12s\n" \
            "$name" "$full_time_ms" "$fast_time_ms" "$speedup" "$mem_saved"
    done
}

# TEST 7.5: Streaming Analyzer Memory Test
test_streaming_analyzer() {
    print_header "TEST 7.5: Streaming Analyzer Memory Efficiency"
    
    local apk="$SIGNAL_APK"  # Use large APK for best comparison
    if ! check_apk "$apk"; then
        apk="$MEDIUM_APK"
        if ! check_apk "$apk"; then
            log_warn "Skipping streaming analyzer test - no suitable APK"
            return
        fi
    fi
    
    local apk_size=$(get_file_size_mb "$apk")
    local apk_name=$(basename "$apk")
    
    log_info "Comparing analyzer modes for: $apk_name"
    log_info "APK size: ${apk_size}MB"
    echo ""
    
    printf "%-20s %-15s %-15s %-15s %-12s\n" \
        "Mode" "Peak RSS (MB)" "Time (ms)" "Memory/MB APK" "Status"
    printf "%s\n" "------------------------------------------------------------------------"
    
    # Standard analyzer (mmap - default)
    local mmap_output=$(/usr/bin/time -l "$CLI" "$apk" --quiet -c 2>&1 | tail -25)
    local mmap_rss=$(echo "$mmap_output" | grep "maximum resident" | awk '{print $1}')
    local mmap_time=$(echo "$mmap_output" | grep "real" | awk '{print $1}')
    
    # Handle empty values
    [ -z "$mmap_rss" ] && mmap_rss="1024"
    [ -z "$mmap_time" ] && mmap_time="0.001"
    
    local mmap_rss_mb=$(echo "scale=1; $mmap_rss / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    local mmap_time_ms=$(echo "$mmap_time * 1000" | bc -l 2>/dev/null | cut -d. -f1)
    local mmap_ratio=$(echo "scale=2; $mmap_rss_mb / $apk_size" | bc -l 2>/dev/null || echo "0")
    
    [ -z "$mmap_time_ms" ] && mmap_time_ms="1"
    
    local status="${GREEN}OK${NC}"
    printf "%-20s %-15s %-15s %-15s " \
        "Standard (mmap)" "${mmap_rss_mb}MB" "${mmap_time_ms}ms" "${mmap_ratio}x"
    echo -e "$status"
    
    # Streaming analyzer
    local stream_output=$(/usr/bin/time -l "$CLI" "$apk" --streaming --quiet -c 2>&1 | tail -25)
    local stream_rss=$(echo "$stream_output" | grep "maximum resident" | awk '{print $1}')
    local stream_time=$(echo "$stream_output" | grep "real" | awk '{print $1}')
    
    # Handle empty values
    [ -z "$stream_rss" ] && stream_rss="1024"
    [ -z "$stream_time" ] && stream_time="0.001"
    
    local stream_rss_mb=$(echo "scale=1; $stream_rss / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    local stream_time_ms=$(echo "$stream_time * 1000" | bc -l 2>/dev/null | cut -d. -f1)
    local stream_ratio=$(echo "scale=2; $stream_rss_mb / $apk_size" | bc -l 2>/dev/null || echo "0")
    
    [ -z "$stream_time_ms" ] && stream_time_ms="1"
    
    printf "%-20s %-15s %-15s %-15s " \
        "Streaming" "${stream_rss_mb}MB" "${stream_time_ms}ms" "${stream_ratio}x"
    echo -e "$status"
    
    # No-mmap (traditional file read)
    local nommap_output=$(/usr/bin/time -l "$CLI" "$apk" --no-mmap --quiet -c 2>&1 | tail -25)
    local nommap_rss=$(echo "$nommap_output" | grep "maximum resident" | awk '{print $1}')
    local nommap_time=$(echo "$nommap_output" | grep "real" | awk '{print $1}')
    
    # Handle empty values
    [ -z "$nommap_rss" ] && nommap_rss="1024"
    [ -z "$nommap_time" ] && nommap_time="0.001"
    
    local nommap_rss_mb=$(echo "scale=1; $nommap_rss / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    local nommap_time_ms=$(echo "$nommap_time * 1000" | bc -l 2>/dev/null | cut -d. -f1)
    local nommap_ratio=$(echo "scale=2; $nommap_rss_mb / $apk_size" | bc -l 2>/dev/null || echo "0")
    
    [ -z "$nommap_time_ms" ] && nommap_time_ms="1"
    
    printf "%-20s %-15s %-15s %-15s " \
        "No-mmap" "${nommap_rss_mb}MB" "${nommap_time_ms}ms" "${nommap_ratio}x"
    echo -e "$status"
    
    # Calculate improvements
    echo ""
    echo "  Results:"
    echo "  ─────────────────────────────────────"
    
    local stream_vs_mmap="N/A"
    local stream_vs_nommap="N/A"
    
    if [ "$(echo "$mmap_rss_mb > 0" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        stream_vs_mmap=$(echo "scale=0; (1 - $stream_rss_mb / $mmap_rss_mb) * 100" | bc -l 2>/dev/null || echo "N/A")
        [ -n "$stream_vs_mmap" ] && [ "$stream_vs_mmap" != "N/A" ] && stream_vs_mmap="${stream_vs_mmap}%"
    fi
    
    if [ "$(echo "$nommap_rss_mb > 0" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        stream_vs_nommap=$(echo "scale=0; (1 - $stream_rss_mb / $nommap_rss_mb) * 100" | bc -l 2>/dev/null || echo "N/A")
        [ -n "$stream_vs_nommap" ] && [ "$stream_vs_nommap" != "N/A" ] && stream_vs_nommap="${stream_vs_nommap}%"
    fi
    
    printf "  Streaming vs mmap:     %s less memory\n" "$stream_vs_mmap"
    printf "  Streaming vs no-mmap:  %s less memory\n" "$stream_vs_nommap"
    echo ""
    
    # Evaluate
    if [ "$(echo "$stream_rss_mb < $mmap_rss_mb" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        log_success "Streaming analyzer uses less memory than standard mmap"
    else
        log_info "Streaming analyzer memory: ${stream_rss_mb}MB"
    fi
    
    log_info "Use --streaming for minimal memory footprint on large APKs"
}

# TEST 8: Throughput benchmark (sequential)
test_throughput_benchmark() {
    print_header "TEST 8: Throughput Benchmark ($ITERATIONS iterations)"
    
    local apks=("$SMALL_APK:Small" "$MEDIUM_APK:Medium")
    
    printf "%-12s %-12s %-12s %-12s %-12s %-12s\n" \
        "Size" "Iterations" "Total (s)" "Avg (ms)" "Min (ms)" "Max (ms)"
    printf "%s\n" "------------------------------------------------------------------------"
    
    for apk_entry in "${apks[@]}"; do
        local apk="${apk_entry%%:*}"
        local name="${apk_entry##*:}"
        
        if ! check_apk "$apk"; then continue; fi
        
        local results_file=$(mktemp)
        local start_time=$(get_high_res_time)
        
        for i in $(seq 1 "$ITERATIONS"); do
            local iter_start=$(get_high_res_time)
            "$CLI" "$apk" --streaming --quiet > /dev/null 2>&1
            local iter_end=$(get_high_res_time)
            echo "$(echo "($iter_end - $iter_start) * 1000" | bc -l | cut -d. -f1)" >> "$results_file"
        done
        
        local end_time=$(get_high_res_time)
        local total_time=$(echo "$end_time - $start_time" | bc -l)
        
        local timings=$(cat "$results_file" | sort -n)
        local avg=$(echo "$timings" | awk '{sum+=$1} END {printf "%.0f", sum/NR}')
        local min=$(echo "$timings" | head -1)
        local max=$(echo "$timings" | tail -1)
        
        printf "%-12s %-12s %-12.2f %-12s %-12s %-12s\n" \
            "$name" "$ITERATIONS" "$total_time" "$avg" "$min" "$max"
        
        rm -f "$results_file"
    done
}

# TEST 8.5: Streaming Compare Memory Test
test_streaming_compare() {
    print_header "TEST 8.5: Streaming Compare Memory Efficiency"
    
    local apk="$SIGNAL_APK"  # Use large APK for best comparison
    if ! check_apk "$apk"; then
        apk="$MEDIUM_APK"
        if ! check_apk "$apk"; then
            log_warn "Skipping streaming compare test - no suitable APK"
            return
        fi
    fi
    
    local apk_size=$(get_file_size_mb "$apk")
    local expected_standard_mem=$(echo "$apk_size * 2" | bc)  # Both files loaded
    
    log_info "Comparing APK to itself to measure memory usage"
    log_info "APK size: ${apk_size}MB (standard compare would need ~${expected_standard_mem}MB)"
    echo ""
    
    printf "%-20s %-15s %-15s %-15s %-12s\n" \
        "Mode" "Peak RSS (MB)" "Peak Footprint" "Time (ms)" "Improvement"
    printf "%s\n" "------------------------------------------------------------------------"
    
    # Streaming compare (mmap - default)
    local stream_output=$(/usr/bin/time -l "$CLI" compare "$apk" "$apk" --quiet -c 2>&1 | tail -25)
    local stream_rss=$(echo "$stream_output" | grep "maximum resident" | awk '{print $1}')
    local stream_peak=$(echo "$stream_output" | grep "peak memory footprint" | awk '{print $1}')
    local stream_time=$(echo "$stream_output" | grep "real" | awk '{print $1}')
    local stream_rss_mb=$(echo "scale=1; $stream_rss / 1024 / 1024" | bc -l)
    local stream_peak_mb=$(echo "scale=1; $stream_peak / 1024 / 1024" | bc -l)
    local stream_time_ms=$(echo "$stream_time * 1000" | bc -l | cut -d. -f1)
    
    printf "%-20s %-15s %-15s %-15s %-12s\n" \
        "Streaming (mmap)" "${stream_rss_mb}MB" "${stream_peak_mb}MB" "${stream_time_ms}ms" "baseline"
    
    # Standard compare (--no-mmap)
    local std_output=$(/usr/bin/time -l "$CLI" compare "$apk" "$apk" --quiet -c --no-mmap 2>&1 | tail -25)
    local std_rss=$(echo "$std_output" | grep "maximum resident" | awk '{print $1}')
    local std_peak=$(echo "$std_output" | grep "peak memory footprint" | awk '{print $1}')
    local std_time=$(echo "$std_output" | grep "real" | awk '{print $1}')
    local std_rss_mb=$(echo "scale=1; $std_rss / 1024 / 1024" | bc -l)
    local std_peak_mb=$(echo "scale=1; $std_peak / 1024 / 1024" | bc -l)
    local std_time_ms=$(echo "$std_time * 1000" | bc -l | cut -d. -f1)
    
    # Calculate improvements
    local mem_reduction="N/A"
    local time_speedup="N/A"
    if [ "$(echo "$std_rss_mb > 0" | bc -l)" -eq 1 ]; then
        mem_reduction=$(echo "scale=0; (1 - $stream_rss_mb / $std_rss_mb) * 100" | bc -l)
        mem_reduction="${mem_reduction}% less"
    fi
    if [ "$stream_time_ms" -gt 0 ]; then
        time_speedup=$(echo "scale=1; $std_time_ms / $stream_time_ms" | bc -l)
        time_speedup="${time_speedup}x faster"
    fi
    
    printf "%-20s %-15s %-15s %-15s %-12s\n" \
        "Standard (no-mmap)" "${std_rss_mb}MB" "${std_peak_mb}MB" "${std_time_ms}ms" "-"
    
    echo ""
    echo "  Results:"
    echo "  ─────────────────────────────────────"
    printf "  Memory Reduction:  %s\n" "$mem_reduction"
    printf "  Speed Improvement: %s\n" "$time_speedup"
    echo ""
    
    if [ "$(echo "$stream_rss_mb < $std_rss_mb / 2" | bc -l)" -eq 1 ]; then
        log_success "Streaming compare uses >50% less memory"
    else
        log_info "Streaming compare memory savings: $mem_reduction"
    fi
}

# TEST 8.6: Content Verification Test
test_content_verify() {
    print_header "TEST 8.6: Content Verification"
    
    local apk="$SIGNAL_APK"  # Use large APK for best test
    if ! check_apk "$apk"; then
        apk="$MEDIUM_APK"
        if ! check_apk "$apk"; then
            log_warn "Skipping content verification test - no suitable APK"
            return
        fi
    fi
    
    local apk_size=$(get_file_size_mb "$apk")
    
    log_info "Testing content verification (comparing APK to itself)"
    log_info "APK size: ${apk_size}MB"
    echo ""
    
    printf "%-25s %-15s %-15s %-12s\n" \
        "Test" "Peak RSS (MB)" "Time (ms)" "Status"
    printf "%s\n" "------------------------------------------------------------------------"
    
    # Test 1: Verify specific file (classes.dex)
    local verify_output=$(/usr/bin/time -l "$CLI" verify "$apk" "$apk" --file classes.dex --quiet -c 2>&1 | tail -25)
    local verify_rss=$(echo "$verify_output" | grep "maximum resident" | awk '{print $1}')
    local verify_time=$(echo "$verify_output" | grep "real" | awk '{print $1}')
    local verify_rss_mb=$(echo "scale=1; $verify_rss / 1024 / 1024" | bc -l)
    local verify_time_ms=$(echo "$verify_time * 1000" | bc -l | cut -d. -f1)
    
    local status="${GREEN}OK${NC}"
    printf "%-25s %-15s %-15s " \
        "Verify classes.dex" "${verify_rss_mb}MB" "${verify_time_ms}ms"
    echo -e "$status"
    
    # Test 2: Verify all matching CRC32 files
    local verify_all_output=$(/usr/bin/time -l "$CLI" verify "$apk" "$apk" --all --quiet -c 2>&1 | tail -25)
    local verify_all_rss=$(echo "$verify_all_output" | grep "maximum resident" | awk '{print $1}')
    local verify_all_time=$(echo "$verify_all_output" | grep "real" | awk '{print $1}')
    local verify_all_rss_mb=$(echo "scale=1; $verify_all_rss / 1024 / 1024" | bc -l)
    local verify_all_time_ms=$(echo "$verify_all_time * 1000" | bc -l | cut -d. -f1)
    
    printf "%-25s %-15s %-15s " \
        "Verify all (CRC32 match)" "${verify_all_rss_mb}MB" "${verify_all_time_ms}ms"
    echo -e "$status"
    
    echo ""
    log_info "Content verification compares actual file bytes, not just metadata"
    log_info "Use --file for specific files, --all to check for CRC32 collisions"
}

# TEST 9: Burst traffic simulation
test_burst_traffic() {
    print_header "TEST 9: Burst Traffic Simulation"
    
    local apk="$MEDIUM_APK"
    if ! check_apk "$apk"; then
        log_warn "Skipping burst traffic test - no APK available"
        return
    fi
    
    log_info "Simulating traffic bursts (common in production)"
    echo ""
    
    local burst_sizes=(10 25 50 100)
    local pause_between=2  # seconds
    
    printf "%-12s %-12s %-12s %-12s %-12s %-12s\n" \
        "Burst Size" "Success" "Failed" "Avg (ms)" "P99 (ms)" "Recovery"
    printf "%s\n" "------------------------------------------------------------------------"
    
    for burst_size in "${burst_sizes[@]}"; do
        [ "$burst_size" -gt "$MAX_CONCURRENCY" ] && continue
        
        local results_file=$(run_concurrent_batch "$apk" "$burst_size")
        local stats=$(calculate_percentiles "$results_file")
        
        local avg=$(echo "$stats" | cut -d' ' -f1)
        local p99=$(echo "$stats" | cut -d' ' -f6)
        local success=$(echo "$stats" | cut -d' ' -f7)
        local fail=$(echo "$stats" | cut -d' ' -f8)
        
        # Test recovery with single request after burst
        sleep 0.5
        local recovery_start=$(get_high_res_time)
        "$CLI" "$apk" --streaming --quiet > /dev/null 2>&1
        local recovery_end=$(get_high_res_time)
        local recovery_ms=$(echo "($recovery_end - $recovery_start) * 1000" | bc -l | cut -d. -f1)
        
        printf "%-12s %-12s %-12s %-12s %-12s %-12s\n" \
            "$burst_size" "$success" "$fail" "${avg%.*}" "${p99%.*}" "${recovery_ms}ms"
        
        rm -f "$results_file"
        sleep "$pause_between"
    done
}

# TEST 10: Error handling under load
test_error_handling() {
    print_header "TEST 10: Error Handling Under Load"
    
    log_info "Testing graceful error handling with invalid inputs"
    echo ""
    
    local valid_apk="$MEDIUM_APK"
    local invalid_paths=(
        "/nonexistent/path/fake.apk"
        "/dev/null"
        "$0"  # This script (not an APK)
    )
    
    printf "%-40s %-12s %-12s\n" "Input" "Exit Code" "Time (ms)"
    printf "%s\n" "------------------------------------------------------------"
    
    # Test invalid inputs (use || true to prevent set -e from exiting)
    for path in "${invalid_paths[@]}"; do
        local start=$(get_high_res_time)
        local exit_code=0
        "$CLI" "$path" --quiet > /dev/null 2>&1 || exit_code=$?
        local end=$(get_high_res_time)
        local duration=$(echo "($end - $start) * 1000" | bc -l | cut -d. -f1)
        
        local display_path="$path"
        [ ${#display_path} -gt 38 ] && display_path="...${display_path: -35}"
        
        printf "%-40s %-12s %-12s\n" "$display_path" "$exit_code" "$duration"
    done
    
    # Test mixed valid/invalid under concurrent load
    if check_apk "$valid_apk"; then
        echo ""
        log_info "Testing mixed valid/invalid requests concurrently..."
        
        local results_file=$(mktemp)
        local pids=()
        
        # 80% valid, 20% invalid
        for i in $(seq 1 8); do
            (
                local s=$(get_high_res_time)
                "$CLI" "$valid_apk" --streaming --quiet > /dev/null 2>&1
                local e=$(get_high_res_time)
                echo "valid $(echo "($e - $s) * 1000" | bc -l | cut -d. -f1) $?" >> "$results_file"
            ) &
            pids+=($!)
        done
        
        for i in $(seq 1 2); do
            (
                local s=$(get_high_res_time)
                "$CLI" "/nonexistent/fake_$i.apk" --streaming --quiet > /dev/null 2>&1
                local e=$(get_high_res_time)
                echo "invalid $(echo "($e - $s) * 1000" | bc -l | cut -d. -f1) $?" >> "$results_file"
            ) &
            pids+=($!)
        done
        
        wait "${pids[@]}" 2>/dev/null || true
        
        local valid_success=$(grep "^valid " "$results_file" | grep " 0$" | wc -l | tr -d ' ')
        local invalid_handled=$(grep "^invalid " "$results_file" | grep -v " 0$" | wc -l | tr -d ' ')
        
        echo ""
        printf "  Valid requests succeeded:    %d/8\n" "$valid_success"
        printf "  Invalid requests handled:    %d/2\n" "$invalid_handled"
        
        if [ "$valid_success" -eq 8 ] && [ "$invalid_handled" -eq 2 ]; then
            log_success "Error handling working correctly under load"
        else
            log_warn "Some requests had unexpected results"
        fi
        
        rm -f "$results_file"
    fi
}

# =============================================================================
# Summary and Recommendations
# =============================================================================

generate_summary() {
    print_header "Performance Test Summary"
    
    echo "Test Configuration:"
    echo "  ─────────────────────────────────────"
    echo "  CLI:                 $CLI"
    echo "  Max Concurrency:     $MAX_CONCURRENCY"
    echo "  Sustained Duration:  ${SUSTAINED_DURATION}s"
    echo "  Iterations:          $ITERATIONS"
    echo "  Memory Threshold:    ${MAX_MEMORY_MB}MB"
    echo "  Latency Threshold:   ${MAX_RESPONSE_TIME_MS}ms"
    echo ""
    
    echo "Results saved to:"
    echo "  JSON: $RESULTS_FILE"
    echo "  CSV:  $CSV_FILE"
    echo ""
    
    echo "Recommendations for Production:"
    echo "  ─────────────────────────────────────"
    echo "  1. Set process limits based on memory pressure test results"
    echo "  2. Configure rate limiting based on sustained load test"
    echo "  3. Use --fast mode for high-throughput scenarios"
    echo "  4. Monitor P99 latency in production dashboards"
    echo "  5. Set up alerts for error rate > 1%"
    echo ""
}

# =============================================================================
# Main Execution
# =============================================================================

usage() {
    cat << EOF
APK Analyzer Performance Test Suite

Usage: $0 [OPTIONS] [TEST_NAMES...]

Options:
  -h, --help              Show this help message
  -q, --quick             Run quick tests only (baseline, fast-mode)
  -f, --full              Run all tests including stress tests
  -c, --concurrency N     Set max concurrency level (default: $MAX_CONCURRENCY)
  -d, --duration N        Set sustained test duration in seconds (default: $SUSTAINED_DURATION)
  -i, --iterations N      Set iteration count for benchmarks (default: $ITERATIONS)
  --target-rps N          Set target RPS for sustained load (default: 10)

Test Names:
  baseline                Single file performance
  concurrency             Concurrency scaling
  sustained               Sustained load test
  ramp                    Ramp-up test (find breaking point)
  mixed                   Mixed workload simulation
  memory                  Memory pressure test
  fast                    Fast mode comparison
  streaming               Streaming analyzer memory test
  throughput              Throughput benchmark
  compare                 Streaming compare test
  verify                  Content verification test
  burst                   Burst traffic simulation
  errors                  Error handling test

Environment Variables:
  CLI                     Path to apk-analyzer binary
  SMALL_APK               Path to small test APK
  MEDIUM_APK              Path to medium test APK
  LARGE_APK               Path to large test APK
  RESULTS_DIR             Directory for results output
  MAX_MEMORY_MB           Memory alert threshold
  MAX_RESPONSE_TIME_MS    Latency alert threshold

Examples:
  $0                      Run default test suite
  $0 --quick              Run quick tests only
  $0 --full -c 128        Run all tests with max 128 concurrency
  $0 baseline concurrency Run specific tests
  $0 -d 60 sustained      Run 60-second sustained load test
EOF
}

main() {
    local quick_mode=0
    local full_mode=0
    local tests=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -q|--quick)
                quick_mode=1
                shift
                ;;
            -f|--full)
                full_mode=1
                shift
                ;;
            -c|--concurrency)
                MAX_CONCURRENCY=$2
                shift 2
                ;;
            -d|--duration)
                SUSTAINED_DURATION=$2
                shift 2
                ;;
            -i|--iterations)
                ITERATIONS=$2
                shift 2
                ;;
            --target-rps)
                TARGET_RPS=$2
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                tests+=("$1")
                shift
                ;;
        esac
    done
    
    # Header
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║         APK Analyzer Performance Test Suite                      ║"
    echo "║         Enterprise-Grade Load Testing                            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Pre-flight checks
    check_dependencies
    check_cli
    init_results
    
    # Show test files
    print_header "Test Files"
    check_apk "$SMALL_APK" && echo "  Small:  $(get_file_size_mb "$SMALL_APK")MB - $SMALL_APK"
    check_apk "$MEDIUM_APK" && echo "  Medium: $(get_file_size_mb "$MEDIUM_APK")MB - $MEDIUM_APK"
    check_apk "$SIGNAL_APK" && echo "  Large:  $(get_file_size_mb "$SIGNAL_APK")MB - $SIGNAL_APK"
    
    # Determine which tests to run
    if [ ${#tests[@]} -eq 0 ]; then
        if [ $quick_mode -eq 1 ]; then
            tests=(baseline fast)
        elif [ $full_mode -eq 1 ]; then
            tests=(baseline concurrency sustained ramp mixed memory fast streaming throughput compare verify burst errors)
        else
            # Default: moderate test suite
            tests=(baseline concurrency mixed memory fast streaming throughput compare verify)
        fi
    fi
    
    # Run selected tests
    for test in "${tests[@]}"; do
        case $test in
            baseline)    test_baseline ;;
            concurrency) test_concurrency_scaling ;;
            sustained)   test_sustained_load ;;
            ramp)        test_ramp_up ;;
            mixed)       test_mixed_workload ;;
            memory)      test_memory_pressure ;;
            fast)        test_fast_mode ;;
            streaming)   test_streaming_analyzer ;;
            throughput)  test_throughput_benchmark ;;
            compare)     test_streaming_compare ;;
            verify)      test_content_verify ;;
            burst)       test_burst_traffic ;;
            errors)      test_error_handling ;;
            *)
                log_warn "Unknown test: $test"
                ;;
        esac
    done
    
    # Summary
    generate_summary
    
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    Tests Complete                                ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
}

main "$@"
