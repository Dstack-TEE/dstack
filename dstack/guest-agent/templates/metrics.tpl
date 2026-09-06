# HELP dstack_guest_info Static system information: OS, kernel and CPU model.
# TYPE dstack_guest_info gauge
dstack_guest_info{os_name="{{system_info.os_name|prometheus_label}}", os_version="{{system_info.os_version|prometheus_label}}", kernel_version="{{system_info.kernel_version|prometheus_label}}", cpu_model="{{system_info.cpu_model|prometheus_label}}"} 1

# HELP dstack_guest_cpus Number of logical CPUs.
# TYPE dstack_guest_cpus gauge
dstack_guest_cpus {{system_info.num_cpus}}

# HELP dstack_guest_memory_total_bytes Total memory in bytes.
# TYPE dstack_guest_memory_total_bytes gauge
dstack_guest_memory_total_bytes {{system_info.total_memory}}

# HELP dstack_guest_memory_available_bytes Available memory in bytes.
# TYPE dstack_guest_memory_available_bytes gauge
dstack_guest_memory_available_bytes {{system_info.available_memory}}

# HELP dstack_guest_memory_used_bytes Used memory in bytes.
# TYPE dstack_guest_memory_used_bytes gauge
dstack_guest_memory_used_bytes {{system_info.used_memory}}

# HELP dstack_guest_memory_free_bytes Free memory in bytes.
# TYPE dstack_guest_memory_free_bytes gauge
dstack_guest_memory_free_bytes {{system_info.free_memory}}

# HELP dstack_guest_swap_total_bytes Total swap in bytes.
# TYPE dstack_guest_swap_total_bytes gauge
dstack_guest_swap_total_bytes {{system_info.total_swap}}

# HELP dstack_guest_swap_used_bytes Used swap in bytes.
# TYPE dstack_guest_swap_used_bytes gauge
dstack_guest_swap_used_bytes {{system_info.used_swap}}

# HELP dstack_guest_swap_free_bytes Free swap in bytes.
# TYPE dstack_guest_swap_free_bytes gauge
dstack_guest_swap_free_bytes {{system_info.free_swap}}

# HELP dstack_guest_uptime_seconds System uptime in seconds.
# TYPE dstack_guest_uptime_seconds gauge
dstack_guest_uptime_seconds {{system_info.uptime}}

# HELP dstack_guest_load1 System load average over 1 minute.
# TYPE dstack_guest_load1 gauge
dstack_guest_load1 {{system_info.loadavg_one}}

# HELP dstack_guest_load5 System load average over 5 minutes.
# TYPE dstack_guest_load5 gauge
dstack_guest_load5 {{system_info.loadavg_five}}

# HELP dstack_guest_load15 System load average over 15 minutes.
# TYPE dstack_guest_load15 gauge
dstack_guest_load15 {{system_info.loadavg_fifteen}}

# HELP dstack_guest_disk_total_bytes Disk size in bytes.
# TYPE dstack_guest_disk_total_bytes gauge
{% for disk in system_info.disks %}
dstack_guest_disk_total_bytes{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {{disk.total_size}}
{% endfor %}

# HELP dstack_guest_disk_free_bytes Free disk space in bytes.
# TYPE dstack_guest_disk_free_bytes gauge
{% for disk in system_info.disks %}
dstack_guest_disk_free_bytes{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {{disk.free_size}}
{% endfor %}

# HELP dstack_guest_disk_used_bytes Used disk space in bytes.
# TYPE dstack_guest_disk_used_bytes gauge
{% for disk in system_info.disks %}
dstack_guest_disk_used_bytes{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {{disk.total_size - disk.free_size}}
{% endfor %}

# HELP dstack_guest_disk_used_ratio Used fraction of the disk, 0 to 1.
# TYPE dstack_guest_disk_used_ratio gauge
{% for disk in system_info.disks %}
dstack_guest_disk_used_ratio{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {% if disk.total_size > 0 %}{{(disk.total_size - disk.free_size) as f64 / disk.total_size as f64}}{% else %}0{% endif %}
{% endfor %}

# HELP dstack_gpu_nvml_up 1 if NVML collection succeeded, 0 otherwise.
# TYPE dstack_gpu_nvml_up gauge
dstack_gpu_nvml_up {% if gpu_info.error.is_empty() %}1{% else %}0{% endif %}

# HELP dstack_gpu_cc_ready 1 if NVIDIA CC GPUs are accepting client requests.
# TYPE dstack_gpu_cc_ready gauge
{% match gpu_info.cc_ready %}
{% when Some with (ready) %}
dstack_gpu_cc_ready {% if ready %}1{% else %}0{% endif %}
{% when None %}
{% endmatch %}

# HELP dstack_gpu_utilization_percent GPU SM duty cycle, percent.
# TYPE dstack_gpu_utilization_percent gauge
{% for gpu in gpu_info.gpus %}
{% match gpu.utilization_gpu %}
{% when Some with (value) %}
dstack_gpu_utilization_percent{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {{value}}
{% when None %}
{% endmatch %}
{% endfor %}

# HELP dstack_gpu_memory_utilization_percent GPU memory-bus duty cycle, percent.
# TYPE dstack_gpu_memory_utilization_percent gauge
{% for gpu in gpu_info.gpus %}
{% match gpu.utilization_memory %}
{% when Some with (value) %}
dstack_gpu_memory_utilization_percent{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {{value}}
{% when None %}
{% endmatch %}
{% endfor %}

# HELP dstack_gpu_memory_total_bytes GPU framebuffer size in bytes.
# TYPE dstack_gpu_memory_total_bytes gauge
{% for gpu in gpu_info.gpus %}
{% match gpu.memory_total_bytes %}
{% when Some with (value) %}
dstack_gpu_memory_total_bytes{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {{value}}
{% when None %}
{% endmatch %}
{% endfor %}

# HELP dstack_gpu_memory_used_bytes GPU framebuffer used in bytes.
# TYPE dstack_gpu_memory_used_bytes gauge
{% for gpu in gpu_info.gpus %}
{% match gpu.memory_used_bytes %}
{% when Some with (value) %}
dstack_gpu_memory_used_bytes{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {{value}}
{% when None %}
{% endmatch %}
{% endfor %}

# HELP dstack_gpu_memory_free_bytes GPU framebuffer free in bytes.
# TYPE dstack_gpu_memory_free_bytes gauge
{% for gpu in gpu_info.gpus %}
{% match gpu.memory_free_bytes %}
{% when Some with (value) %}
dstack_gpu_memory_free_bytes{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {{value}}
{% when None %}
{% endmatch %}
{% endfor %}

# HELP dstack_gpu_temperature_celsius GPU temperature in Celsius.
# TYPE dstack_gpu_temperature_celsius gauge
{% for gpu in gpu_info.gpus %}
{% match gpu.temperature_c %}
{% when Some with (value) %}
dstack_gpu_temperature_celsius{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {{value}}
{% when None %}
{% endmatch %}
{% endfor %}

# HELP dstack_gpu_power_usage_milliwatts GPU power usage in milliwatts.
# TYPE dstack_gpu_power_usage_milliwatts gauge
{% for gpu in gpu_info.gpus %}
{% match gpu.power_usage_mw %}
{% when Some with (value) %}
dstack_gpu_power_usage_milliwatts{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {{value}}
{% when None %}
{% endmatch %}
{% endfor %}

# HELP dstack_gpu_query_errors Number of NVML field queries that failed on this GPU.
# TYPE dstack_gpu_query_errors gauge
{% for gpu in gpu_info.gpus %}
dstack_gpu_query_errors{index="{{gpu.index}}", uuid="{{gpu.uuid|prometheus_label}}", pci_bus_id="{{gpu.pci_bus_id|prometheus_label}}"} {% if gpu.error.is_empty() %}0{% else %}{{ gpu.error.split("; ").count() }}{% endif %}
{% endfor %}

# Everything below is the pre-rename exposition, kept verbatim so existing
# dashboards keep working through one release cycle. Deprecated: use the
# dstack_guest_* series above; these will be removed in a future release.

# HELP system_os_name Operating system name (deprecated: use dstack_guest_info)
# TYPE system_os_name gauge
system_os_name{os_name="{{system_info.os_name|prometheus_label}}"} 1

# HELP system_os_version Operating system version (deprecated: use dstack_guest_info)
# TYPE system_os_version gauge
system_os_version{os_version="{{system_info.os_version|prometheus_label}}"} 1

# HELP system_kernel_version Kernel version (deprecated: use dstack_guest_info)
# TYPE system_kernel_version gauge
system_kernel_version{kernel_version="{{system_info.kernel_version|prometheus_label}}"} 1

# HELP system_cpu_model CPU model information (deprecated: use dstack_guest_info)
# TYPE system_cpu_model gauge
system_cpu_model{cpu_model="{{system_info.cpu_model|prometheus_label}}"} 1

# HELP system_num_cpus Number of logical CPUs (deprecated: use dstack_guest_cpus)
# TYPE system_num_cpus gauge
system_num_cpus {{system_info.num_cpus}}

# HELP system_memory_total Total memory in bytes (deprecated: use dstack_guest_memory_total_bytes)
# TYPE system_memory_total gauge
system_memory_total {{system_info.total_memory}}

# HELP system_memory_available Available memory in bytes (deprecated: use dstack_guest_memory_available_bytes)
# TYPE system_memory_available gauge
system_memory_available {{system_info.available_memory}}

# HELP system_memory_used Used memory in bytes (deprecated: use dstack_guest_memory_used_bytes)
# TYPE system_memory_used gauge
system_memory_used {{system_info.used_memory}}

# HELP system_memory_free Free memory in bytes (deprecated: use dstack_guest_memory_free_bytes)
# TYPE system_memory_free gauge
system_memory_free {{system_info.free_memory}}

# HELP system_swap_total Total swap memory in bytes (deprecated: use dstack_guest_swap_total_bytes)
# TYPE system_swap_total gauge
system_swap_total {{system_info.total_swap}}

# HELP system_swap_used Used swap memory in bytes (deprecated: use dstack_guest_swap_used_bytes)
# TYPE system_swap_used gauge
system_swap_used {{system_info.used_swap}}

# HELP system_swap_free Free swap memory in bytes (deprecated: use dstack_guest_swap_free_bytes)
# TYPE system_swap_free gauge
system_swap_free {{system_info.free_swap}}

# HELP system_uptime System uptime in seconds (deprecated: use dstack_guest_uptime_seconds)
# TYPE system_uptime gauge
system_uptime {{system_info.uptime}}

# HELP system_load_average_1m System load average (1 minute) (deprecated: use dstack_guest_load1)
# TYPE system_load_average_1m gauge
system_load_average_1m {{system_info.loadavg_one}}

# HELP system_load_average_5m System load average (5 minutes) (deprecated: use dstack_guest_load5)
# TYPE system_load_average_5m gauge
system_load_average_5m {{system_info.loadavg_five}}

# HELP system_load_average_15m System load average (15 minutes) (deprecated: use dstack_guest_load15)
# TYPE system_load_average_15m gauge
system_load_average_15m {{system_info.loadavg_fifteen}}

# HELP disk_total_size Disk total size in bytes (deprecated: use dstack_guest_disk_total_bytes)
# TYPE disk_total_size gauge
{% for disk in system_info.disks %}
disk_total_size{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {{disk.total_size}}
{% endfor %}

# HELP disk_free_size Disk free size in bytes (deprecated: use dstack_guest_disk_free_bytes)
# TYPE disk_free_size gauge
{% for disk in system_info.disks %}
disk_free_size{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {{disk.free_size}}
{% endfor %}

# HELP disk_used_size Disk used size in bytes (deprecated: use dstack_guest_disk_used_bytes)
# TYPE disk_used_size gauge
{% for disk in system_info.disks %}
disk_used_size{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {{disk.total_size - disk.free_size}}
{% endfor %}

# HELP disk_usage_percentage Disk usage percentage (deprecated: use dstack_guest_disk_used_ratio)
# TYPE disk_usage_percentage gauge
{% for disk in system_info.disks %}
disk_usage_percentage{name="{{disk.name|prometheus_label}}", mount_point="{{disk.mount_point|prometheus_label}}"} {% if disk.total_size > 0 %}{{(disk.total_size - disk.free_size) as f64 / disk.total_size as f64 * 100.0}}{% else %}0{% endif %}
{% endfor %}
