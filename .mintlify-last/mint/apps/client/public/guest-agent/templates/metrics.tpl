# HELP system_os_name Operating system name
# TYPE system_os_name gauge
system_os_name{os_name="{{system_info.os_name}}"} 1

# HELP system_os_version Operating system version
# TYPE system_os_version gauge
system_os_version{os_version="{{system_info.os_version}}"} 1

# HELP system_kernel_version Kernel version
# TYPE system_kernel_version gauge
system_kernel_version{kernel_version="{{system_info.kernel_version}}"} 1

# HELP system_cpu_model CPU model information
# TYPE system_cpu_model gauge
system_cpu_model{cpu_model="{{system_info.cpu_model}}"} 1

# HELP system_num_cpus Number of logical CPUs
# TYPE system_num_cpus gauge
system_num_cpus {{system_info.num_cpus}}

# HELP system_memory_total Total memory in bytes
# TYPE system_memory_total gauge
system_memory_total {{system_info.total_memory}}

# HELP system_memory_available Available memory in bytes
# TYPE system_memory_available gauge
system_memory_available {{system_info.available_memory}}

# HELP system_memory_used Used memory in bytes
# TYPE system_memory_used gauge
system_memory_used {{system_info.used_memory}}

# HELP system_memory_free Free memory in bytes
# TYPE system_memory_free gauge
system_memory_free {{system_info.free_memory}}

# HELP system_swap_total Total swap memory in bytes
# TYPE system_swap_total gauge
system_swap_total {{system_info.total_swap}}

# HELP system_swap_used Used swap memory in bytes
# TYPE system_swap_used gauge
system_swap_used {{system_info.used_swap}}

# HELP system_swap_free Free swap memory in bytes
# TYPE system_swap_free gauge
system_swap_free {{system_info.free_swap}}

# HELP system_uptime System uptime in seconds
# TYPE system_uptime gauge
system_uptime {{system_info.uptime}}

# HELP system_load_average_1m System load average (1 minute)
# TYPE system_load_average_1m gauge
system_load_average_1m {{system_info.loadavg_one}}

# HELP system_load_average_5m System load average (5 minutes)
# TYPE system_load_average_5m gauge
system_load_average_5m {{system_info.loadavg_five}}

# HELP system_load_average_15m System load average (15 minutes)
# TYPE system_load_average_15m gauge
system_load_average_15m {{system_info.loadavg_fifteen}}

# HELP disk_total_size Disk total size in bytes
# TYPE disk_total_size gauge
{% for disk in system_info.disks %}
disk_total_size{name="{{disk.name}}", mount_point="{{disk.mount_point}}"} {{disk.total_size}}
{% endfor %}

# HELP disk_free_size Disk free size in bytes
# TYPE disk_free_size gauge
{% for disk in system_info.disks %}
disk_free_size{name="{{disk.name}}", mount_point="{{disk.mount_point}}"} {{disk.free_size}}
{% endfor %}

# HELP disk_used_size Disk used size in bytes
# TYPE disk_used_size gauge
{% for disk in system_info.disks %}
disk_used_size{name="{{disk.name}}", mount_point="{{disk.mount_point}}"} {{disk.total_size - disk.free_size}}
{% endfor %}

# HELP disk_usage_percentage Disk usage percentage
# TYPE disk_usage_percentage gauge
{% for disk in system_info.disks %}
disk_usage_percentage{name="{{disk.name}}", mount_point="{{disk.mount_point}}"} {% if disk.total_size > 0 %}{{(disk.total_size - disk.free_size) as f64 / disk.total_size as f64 * 100.0}}{% else %}0{% endif %}
{% endfor %}
