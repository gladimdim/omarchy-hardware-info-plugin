#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import re
import time

CACHE_FILE = "/tmp/omarchy-hardware-static-cache.json"

def read_file(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception:
        return default

def get_static_hardware():
    # Check cache first (valid for 1 day)
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cached = json.load(f)
                if time.time() - cached.get("_cache_time", 0) < 86400:
                    return cached
        except Exception:
            pass

    # 1. DMI Info
    dmi_dir = "/sys/class/dmi/id"
    fields = {
        "board_vendor": "board_vendor",
        "board_name": "board_name",
        "board_version": "board_version",
        "bios_vendor": "bios_vendor",
        "bios_version": "bios_version",
        "bios_date": "bios_date",
        "product_name": "product_name",
        "product_family": "product_family",
        "product_version": "product_version",
        "chassis_type": "chassis_type",
        "sys_vendor": "sys_vendor"
    }
    dmi = {}
    for k, v in fields.items():
        dmi[k] = read_file(f"{dmi_dir}/{v}")
    
    chassis_map = {
        "1": "Other", "2": "Unknown", "3": "Desktop", "4": "Low Profile Desktop",
        "8": "Portable", "9": "Laptop", "10": "Notebook", "11": "Hand Held",
        "13": "All in One", "14": "Sub Notebook", "30": "Tablet", "31": "Convertible", "32": "Detachable"
    }
    raw_chassis = dmi.get("chassis_type", "")
    dmi["chassis_desc"] = chassis_map.get(raw_chassis, f"Type {raw_chassis}" if raw_chassis else "Notebook")

    # 2. CPU Specs & Capabilities
    lscpu_data = {}
    try:
        out = subprocess.check_output(["lscpu", "--json"], text=True, stderr=subprocess.DEVNULL)
        lscpu_json = json.loads(out)
        for item in lscpu_json.get("lscpu", []):
            field = item.get("field", "").rstrip(":")
            data = item.get("data")
            if field:
                lscpu_data[field] = data
            for child in item.get("children", []):
                cfield = child.get("field", "").rstrip(":")
                cdata = child.get("data")
                if cfield:
                    lscpu_data[cfield] = cdata
                for grandchild in child.get("children", []):
                    gfield = grandchild.get("field", "").rstrip(":")
                    gdata = grandchild.get("data")
                    if gfield:
                        lscpu_data[gfield] = gdata
    except Exception:
        pass

    flags = set()
    model_name = lscpu_data.get("Model name", "")
    vendor_id = lscpu_data.get("Vendor ID", "")
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("flags") or line.startswith("Features"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        flags.update(parts[1].strip().split())
                elif not model_name and line.startswith("model name"):
                    model_name = line.split(":", 1)[1].strip()
                elif not vendor_id and line.startswith("vendor_id"):
                    vendor_id = line.split(":", 1)[1].strip()
    except Exception:
        pass

    caches = {
        "l1d": lscpu_data.get("L1d", "192 KiB (4 instances)"),
        "l1i": lscpu_data.get("L1i", "128 KiB (4 instances)"),
        "l2": lscpu_data.get("L2", "5 MiB (4 instances)"),
        "l3": lscpu_data.get("L3", "12 MiB (1 instance)")
    }

    flag_set = set(f.lower() for f in flags)
    def has_flag(f):
        return f.lower() in flag_set

    capabilities = {
        "simd": [],
        "crypto": [],
        "virtualization": [],
        "security": [],
        "performance": []
    }

    simd_checks = [
        ("AVX-512 Foundation", "avx512f"),
        ("AVX-512 Byte/Word", "avx512bw"),
        ("AVX-512 Double/Quad", "avx512dq"),
        ("AVX-512 Vector Length", "avx512vl"),
        ("AVX-512 VNNI (AI/DL)", "avx512_vnni"),
        ("AVX-512 VBMI / VBMI2", "avx512vbmi"),
        ("AVX-512 Bit Alg", "avx512_bitalg"),
        ("AVX-512 Popcnt", "avx512_vpopcntdq"),
        ("AVX2", "avx2"),
        ("AVX", "avx"),
        ("FMA3", "fma"),
        ("SSE 4.2", "sse4_2"),
        ("SSE 4.1", "sse4_1"),
        ("SSSE 3", "ssse3"),
        ("SSE 2", "sse2"),
        ("MMX", "mmx")
    ]
    for label, flg in simd_checks:
        capabilities["simd"].append({"name": label, "flag": flg, "supported": has_flag(flg)})

    crypto_checks = [
        ("AES-NI", "aes"),
        ("VAES (Vector AES)", "vaes"),
        ("SHA-NI", "sha_ni"),
        ("Galois Field (GFNI)", "gfni"),
        ("RDRAND (Hardware RNG)", "rdrand"),
        ("RDSEED (True RNG)", "rdseed"),
        ("PCLMULQDQ", "pclmulqdq")
    ]
    for label, flg in crypto_checks:
        capabilities["crypto"].append({"name": label, "flag": flg, "supported": has_flag(flg)})

    virt_checks = [
        ("Intel VT-x (VMX)", "vmx"),
        ("Extended Page Tables (EPT)", "ept"),
        ("Virtual Processor ID (VPID)", "vpid"),
        ("Nested Virtualization (VNMI)", "vnmi")
    ]
    for label, flg in virt_checks:
        capabilities["virtualization"].append({"name": label, "flag": flg, "supported": has_flag(flg)})

    sec_checks = [
        ("Supervisor Mode Execution (SMEP)", "smep"),
        ("Supervisor Mode Access (SMAP)", "smap"),
        ("User Shadow Stack (CET/SHSTK)", "user_shstk"),
        ("Indirect Branch Speculation (IBRS)", "ibrs"),
        ("Indirect Branch Prediction (IBPB)", "ibpb"),
        ("Speculative Store Bypass (SSBD)", "ssbd"),
        ("Protection Keys (PKU/OSPKE)", "pku"),
        ("User Instruction Prevention (UMIP)", "umip"),
        ("Microarchitectural Buffer Clear", "md_clear")
    ]
    for label, flg in sec_checks:
        capabilities["security"].append({"name": label, "flag": flg, "supported": has_flag(flg)})

    perf_checks = [
        ("Intel Speed Shift (HWP)", "hwp"),
        ("Intel Turbo Boost (IDA)", "ida"),
        ("Fast Short REP MOVSB (FSRM)", "fsrm"),
        ("Invariant TSC", "constant_tsc"),
        ("TSC Deadline Timer", "tsc_deadline_timer"),
        ("CLFLUSHOPT", "clflushopt"),
        ("CLWB (Cache Line Write Back)", "clwb"),
        ("MOVDIR64B (Direct 64B Store)", "movdir64b")
    ]
    for label, flg in perf_checks:
        capabilities["performance"].append({"name": label, "flag": flg, "supported": has_flag(flg)})

    base_mhz = lscpu_data.get("CPU base MHz", "")
    if not base_mhz:
        m = re.search(r"@\s*([\d\.]+)GHz", model_name)
        if m:
            try:
                base_mhz = str(int(float(m.group(1)) * 1000))
            except Exception:
                base_mhz = "2800"
        else:
            base_mhz = "2800"

    max_mhz = lscpu_data.get("CPU max MHz", "4700")
    try:
        max_mhz = str(int(float(max_mhz)))
    except Exception:
        pass

    min_mhz = lscpu_data.get("CPU min MHz", "400")
    try:
        min_mhz = str(int(float(min_mhz)))
    except Exception:
        pass

    cpu_static = {
        "model": model_name,
        "vendor": vendor_id,
        "arch": lscpu_data.get("Architecture", "x86_64"),
        "cores": lscpu_data.get("Core(s) per socket", "4"),
        "threads": lscpu_data.get("CPU(s)", "8"),
        "sockets": lscpu_data.get("Socket(s)", "1"),
        "threads_per_core": lscpu_data.get("Thread(s) per core", "2"),
        "base_mhz": base_mhz,
        "max_mhz": max_mhz,
        "min_mhz": min_mhz,
        "caches": caches,
        "virtualization": lscpu_data.get("Virtualization", "VT-x"),
        "capabilities": capabilities,
        "all_flags": sorted(list(flags))
    }

    # 3. RAM Modules & Channels from inxi
    modules = []
    array_summary = ""
    try:
        out = subprocess.check_output(["inxi", "-m", "-c", "0"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Array-1:") or line.startswith("Array:"):
                array_summary = line
            elif line.startswith("Device-"):
                m = re.search(r"Device-\d+:\s*(\S+)\s+type:\s*(\S+)\s+size:\s*([\d\.]+\s*\S+)\s+speed:\s*([\d\.]+\s*\S+)", line)
                if m:
                    modules.append({
                        "slot": m.group(1),
                        "type": m.group(2),
                        "size": m.group(3),
                        "speed": m.group(4)
                    })
    except Exception:
        pass

    # 4. Physical Disks
    disks = []
    try:
        out = subprocess.check_output(["lsblk", "--json", "-o", "NAME,SIZE,TYPE,MODEL,SERIAL,TRAN"], text=True, stderr=subprocess.DEVNULL)
        data = json.loads(out)
        for dev in data.get("blockdevices", []):
            if dev.get("type") == "disk":
                name = dev.get("name", "")
                model = dev.get("model") or ("ZRAM Block Device" if "zram" in name else "Unknown Disk")
                tran = (dev.get("tran") or "").upper()
                if not tran and "nvme" in name:
                    tran = "NVME"
                elif not tran and "zram" in name:
                    tran = "RAM"
                disks.append({
                    "name": name,
                    "model": model,
                    "size": dev.get("size", ""),
                    "tran": tran,
                    "serial": dev.get("serial") or "—"
                })
    except Exception:
        pass

    # 5. PCI Devices (GPU, Network, Audio)
    gpus = []
    network = []
    audio = []
    try:
        out = subprocess.check_output(["lspci"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            slot = parts[0]
            desc = parts[1] if len(parts) > 1 else ""
            low = desc.lower()
            if "vga" in low or "3d" in low or "display" in low:
                gpus.append({"slot": slot, "name": desc})
            elif "network" in low or "wireless" in low or "ethernet" in low:
                network.append({"slot": slot, "name": desc})
            elif "audio" in low or "sound" in low:
                audio.append({"slot": slot, "name": desc})
    except Exception:
        pass

    res = {
        "_cache_time": time.time(),
        "dmi": dmi,
        "cpu_static": cpu_static,
        "memory_static": {
            "array_summary": array_summary,
            "modules": modules
        },
        "disks": disks,
        "devices": {
            "gpus": gpus,
            "network": network,
            "audio": audio
        }
    }

    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(res, f)
    except Exception:
        pass

    return res

def get_dynamic_stats(static_data):
    # 1. OS & Uptime
    hostname = read_file("/etc/hostname", "gladimdim-b9")
    kernel = read_file("/proc/sys/kernel/osrelease", "")
    uptime_sec = 0.0
    try:
        uptime_sec = float(read_file("/proc/uptime").split()[0])
    except Exception:
        pass
    days = int(uptime_sec // 86400)
    hours = int((uptime_sec % 86400) // 3600)
    mins = int((uptime_sec % 3600) // 60)
    uptime_str = f"{days}d {hours}h {mins}m" if days > 0 else f"{hours}h {mins}m"

    distro_name = "Omarchy"
    for line in read_file("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            distro_name = line.split("=", 1)[1].strip('"\x27')
            break

    os_info = {
        "hostname": hostname,
        "kernel": kernel,
        "distro": distro_name,
        "uptime": uptime_str,
        "uptime_sec": uptime_sec
    }

    # 2. CPU Dynamic
    core_freqs = []
    cpu_dir = "/sys/devices/system/cpu"
    for i in range(128):
        cpath = f"{cpu_dir}/cpu{i}/cpufreq"
        if not os.path.exists(cpath):
            break
        cur = read_file(f"{cpath}/scaling_cur_freq")
        if cur:
            try:
                core_freqs.append(round(int(cur) / 1000, 1))
            except Exception:
                pass

    gov = read_file(f"{cpu_dir}/cpu0/cpufreq/scaling_governor", "powersave")
    driver = read_file(f"{cpu_dir}/cpu0/cpufreq/scaling_driver", "intel_pstate")
    loadavg = read_file("/proc/loadavg", "0 0 0").split()[:3]

    vulns = []
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    if os.path.exists(vuln_dir):
        for vname in sorted(os.listdir(vuln_dir)):
            status = read_file(f"{vuln_dir}/{vname}")
            is_mitigated = "Mitigation" in status or "Not affected" in status
            vulns.append({
                "name": vname.replace("_", " ").title(),
                "status": status,
                "is_mitigated": is_mitigated
            })

    cpu_info = dict(static_data.get("cpu_static", {}))
    cpu_info.update({
        "governor": gov,
        "driver": driver,
        "core_freqs_mhz": core_freqs,
        "load_avg": loadavg,
        "vulnerabilities": vulns
    })

    # 3. Memory Dynamic
    meminfo = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    k = parts[0].strip()
                    val = parts[1].strip().split()[0]
                    try:
                        meminfo[k] = int(val)
                    except Exception:
                        pass
    except Exception:
        pass

    total_kb = meminfo.get("MemTotal", 0)
    avail_kb = meminfo.get("MemAvailable", 0)
    free_kb = meminfo.get("MemFree", 0)
    cached_kb = meminfo.get("Cached", 0)
    buffers_kb = meminfo.get("Buffers", 0)
    swap_total_kb = meminfo.get("SwapTotal", 0)
    swap_free_kb = meminfo.get("SwapFree", 0)
    
    used_kb = total_kb - avail_kb if total_kb >= avail_kb else (total_kb - free_kb)
    swap_used_kb = swap_total_kb - swap_free_kb

    mem_static = static_data.get("memory_static", {})
    memory_info = {
        "total_gb": round(total_kb / 1048576, 2),
        "used_gb": round(used_kb / 1048576, 2),
        "avail_gb": round(avail_kb / 1048576, 2),
        "free_gb": round(free_kb / 1048576, 2),
        "cached_gb": round(cached_kb / 1048576, 2),
        "buffers_mb": round(buffers_kb / 1024, 1),
        "used_pct": round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0,
        "swap_total_gb": round(swap_total_kb / 1048576, 2),
        "swap_used_gb": round(swap_used_kb / 1048576, 2),
        "swap_free_gb": round(swap_free_kb / 1048576, 2),
        "swap_used_pct": round((swap_used_kb / swap_total_kb) * 100, 1) if swap_total_kb > 0 else 0,
        "array_summary": mem_static.get("array_summary", ""),
        "modules": mem_static.get("modules", [])
    }

    # 4. Storage Mounts Dynamic
    mounts = []
    try:
        out = subprocess.check_output(["lsblk", "--json", "-o", "NAME,SIZE,TYPE,MOUNTPOINTS,FSTYPE,FSAVAIL,FSUSED,FSUSE%"], text=True, stderr=subprocess.DEVNULL)
        data = json.loads(out)
        def walk_dev(dev):
            mps = dev.get("mountpoints", [])
            if mps:
                for mp in mps:
                    if mp and mp != "null":
                        mounts.append({
                            "device": dev.get("name", ""),
                            "mountpoint": mp,
                            "size": dev.get("size", ""),
                            "fstype": dev.get("fstype", "") or "—",
                            "used": dev.get("fsused", "") or "—",
                            "avail": dev.get("fsavail", "") or "—",
                            "use_pct": dev.get("fsuse%", "") or "0%"
                        })
            for child in dev.get("children", []):
                walk_dev(child)
        for dev in data.get("blockdevices", []):
            walk_dev(dev)
    except Exception:
        pass

    storage_info = {
        "disks": static_data.get("disks", []),
        "mounts": mounts
    }

    # 5. Sensors Dynamic
    sensors_data = {
        "cpu_temp_c": None,
        "nvme_temp_c": None,
        "fan_rpm": None,
        "battery_watts": None
    }
    try:
        out = subprocess.check_output(["sensors"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if "Package id 0:" in line or "Package id 0" in line:
                m = re.search(r"\+([\d\.]+)\s*°C", line)
                if m:
                    sensors_data["cpu_temp_c"] = float(m.group(1))
            elif re.search(r"\b(?:cpu_fan|fan\d*|exhaust)\s*:", line, re.IGNORECASE):
                m = re.search(r"(\d+)\s*RPM", line)
                if m:
                    sensors_data["fan_rpm"] = int(m.group(1))
            elif "Composite:" in line:
                m = re.search(r"\+([\d\.]+)\s*°C", line)
                if m:
                    sensors_data["nvme_temp_c"] = float(m.group(1))
            elif "power1:" in line:
                m = re.search(r"([\d\.]+)\s*W", line)
                if m:
                    sensors_data["battery_watts"] = float(m.group(1))
    except Exception:
        pass

    if sensors_data["cpu_temp_c"] is None:
        try:
            for i in range(10):
                tpath = f"/sys/class/thermal/thermal_zone{i}"
                if os.path.exists(tpath):
                    ttype = read_file(f"{tpath}/type")
                    if "x86_pkg_temp" in ttype or "acpitz" in ttype:
                        raw = read_file(f"{tpath}/temp")
                        if raw:
                            sensors_data["cpu_temp_c"] = round(int(raw) / 1000, 1)
                            break
        except Exception:
            pass

    return {
        "timestamp": int(time.time()),
        "os": os_info,
        "dmi": static_data.get("dmi", {}),
        "cpu": cpu_info,
        "memory": memory_info,
        "storage": storage_info,
        "devices": static_data.get("devices", {}),
        "sensors": sensors_data
    }

def collect_all():
    static_data = get_static_hardware()
    return get_dynamic_stats(static_data)

if __name__ == "__main__":
    t0 = time.time()
    data = collect_all()
    if "--pretty" in sys.argv:
        print(json.dumps(data, indent=2))
    elif "--time" in sys.argv:
        print(f"Collected in {(time.time() - t0)*1000:.2f} ms")
        print(json.dumps(data))
    else:
        print(json.dumps(data))
