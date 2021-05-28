targets rpi3.a53.3
halt
targets rpi3.a53.2
halt
targets rpi3.a53.1
halt
targets rpi3.a53.0
halt
log_output raspi2.reg
# dump registers first (r0 might be overwritten later)
echo -n [reg r0]
echo -n [reg r1]
echo -n [reg r2]
echo -n [reg r3]
echo -n [reg r4]
echo -n [reg r5]
echo -n [reg r6]
echo -n [reg r7]
echo -n [reg r8]
echo -n [reg r9]
echo -n [reg r10]
echo -n [reg r11]
echo -n [reg r12]
echo -n [reg sp_usr]
echo -n [reg lr_usr]
echo -n [reg pc]
echo -n [reg r8_fiq]
echo -n [reg r9_fiq]
echo -n [reg r10_fiq]
echo -n [reg r11_fiq]
echo -n [reg r12_fiq]
echo -n [reg sp_fiq]
echo -n [reg lr_fiq]
echo -n [reg sp_irq]
echo -n [reg lr_irq]
echo -n [reg sp_svc]
echo -n [reg lr_svc]
echo -n [reg sp_abt]
echo -n [reg lr_abt]
echo -n [reg sp_und]
echo -n [reg lr_und]
echo -n [reg cpsr]
echo -n [reg spsr_fiq]
echo -n [reg spsr_irq]
echo -n [reg spsr_svc]
echo -n [reg spsr_abt]
echo -n [reg spsr_und]
echo -n [reg sp]
echo -n [reg lr]
echo -n [reg sp_mon]
echo -n [reg lr_mon]
echo -n [reg spsr_mon]
#echo -n [reg d0]
#echo -n [reg d1]
#echo -n [reg d2]
#echo -n [reg d3]
#echo -n [reg d4]
#echo -n [reg d5]
#echo -n [reg d6]
#echo -n [reg d7]
#echo -n [reg d8]
#echo -n [reg d9]
#echo -n [reg d10]
#echo -n [reg d11]
#echo -n [reg d12]
#echo -n [reg d13]
#echo -n [reg d14]
#echo -n [reg d15]
#echo -n [reg d16]
#echo -n [reg d17]
#echo -n [reg d18]
#echo -n [reg d19]
#echo -n [reg d20]
#echo -n [reg d21]
#echo -n [reg d22]
#echo -n [reg d23]
#echo -n [reg d24]
#echo -n [reg d25]
#echo -n [reg d26]
#echo -n [reg d27]
#echo -n [reg d28]
#echo -n [reg d29]
#echo -n [reg d30]
# Main ID
echo [format "main_id_0 = %#x" [aarch64 mrc 15 0 0 0 0]]
echo [format "main_id_1 = %#x" [aarch64 mrc 15 0 0 0 4]]
echo [format "main_id_2 = %#x" [aarch64 mrc 15 0 0 0 6]]
echo [format "main_id_3 = %#x" [aarch64 mrc 15 0 0 0 7]]
# Cache Type
echo [format "cache_type_0 = %#x" [aarch64 mrc 15 0 0 0 1]]
# TCM Type
echo [format "tcm_type_0 = %#x" [aarch64 mrc 15 0 0 0 2]]
# TLB Type
echo [format "tlb_type_0 = %#x" [aarch64 mrc 15 0 0 0 3]]
# Multiprocessor ID
echo [format "multiprocessor_id_0 = %#x" [aarch64 mrc 15 0 0 0 5]]
# Processor Feature 0
echo [format "processor_feature_0_0 = %#x" [aarch64 mrc 15 0 0 1 0]]
# Processor Feature 1
echo [format "processor_feature_1_0 = %#x" [aarch64 mrc 15 0 0 1 1]]
# Debug Feature 0
echo [format "debug_feature_0_0 = %#x" [aarch64 mrc 15 0 0 1 2]]
# Auxiliary Feature 0
echo [format "auxiliary_feature_0_0 = %#x" [aarch64 mrc 15 0 0 1 3]]
# Memory Model Feature 0
echo [format "memory_model_feature_0_0 = %#x" [aarch64 mrc 15 0 0 1 4]]
# Memory Model Feature 1
echo [format "memory_model_feature_1_0 = %#x" [aarch64 mrc 15 0 0 1 5]]
# Memory Model Feature 2
echo [format "memory_model_feature_2_0 = %#x" [aarch64 mrc 15 0 0 1 6]]
# Memory Model Feature 3
echo [format "memory_model_feature_3_0 = %#x" [aarch64 mrc 15 0 0 1 7]]
# Instruction Set Attribute 0
echo [format "instruction_set_attribute_0_0 = %#x" [aarch64 mrc 15 0 0 2 0]]
# Instruction Set Attribute 1
echo [format "instruction_set_attribute_1_0 = %#x" [aarch64 mrc 15 0 0 2 1]]
# Instruction Set Attribute 2
echo [format "instruction_set_attribute_2_0 = %#x" [aarch64 mrc 15 0 0 2 2]]
# Instruction Set Attribute 3
echo [format "instruction_set_attribute_3_0 = %#x" [aarch64 mrc 15 0 0 2 3]]
# Instruction Set Attribute 4
echo [format "instruction_set_attribute_4_0 = %#x" [aarch64 mrc 15 0 0 2 4]]
# Instruction Set Attribute 5-7
echo [format "instruction_set_attribute_5-7_0 = %#x" [aarch64 mrc 15 0 0 2 5]]
echo [format "instruction_set_attribute_5-7_1 = %#x" [aarch64 mrc 15 0 0 2 6]]
echo [format "instruction_set_attribute_5-7_2 = %#x" [aarch64 mrc 15 0 0 2 7]]
# Reserved for Feature ID Registers
echo [format "reserved_for_feature_id_registers_0 = %#x" [aarch64 mrc 15 0 0 3 0]]
echo [format "reserved_for_feature_id_registers_1 = %#x" [aarch64 mrc 15 0 0 3 1]]
echo [format "reserved_for_feature_id_registers_2 = %#x" [aarch64 mrc 15 0 0 3 2]]
echo [format "reserved_for_feature_id_registers_3 = %#x" [aarch64 mrc 15 0 0 3 3]]
echo [format "reserved_for_feature_id_registers_4 = %#x" [aarch64 mrc 15 0 0 3 4]]
echo [format "reserved_for_feature_id_registers_5 = %#x" [aarch64 mrc 15 0 0 3 5]]
echo [format "reserved_for_feature_id_registers_6 = %#x" [aarch64 mrc 15 0 0 3 6]]
echo [format "reserved_for_feature_id_registers_7 = %#x" [aarch64 mrc 15 0 0 3 7]]
echo [format "reserved_for_feature_id_registers_8 = %#x" [aarch64 mrc 15 0 0 4 0]]
echo [format "reserved_for_feature_id_registers_9 = %#x" [aarch64 mrc 15 0 0 4 1]]
echo [format "reserved_for_feature_id_registers_10 = %#x" [aarch64 mrc 15 0 0 4 2]]
echo [format "reserved_for_feature_id_registers_11 = %#x" [aarch64 mrc 15 0 0 4 3]]
echo [format "reserved_for_feature_id_registers_12 = %#x" [aarch64 mrc 15 0 0 4 4]]
echo [format "reserved_for_feature_id_registers_13 = %#x" [aarch64 mrc 15 0 0 4 5]]
echo [format "reserved_for_feature_id_registers_14 = %#x" [aarch64 mrc 15 0 0 4 6]]
echo [format "reserved_for_feature_id_registers_15 = %#x" [aarch64 mrc 15 0 0 4 7]]
echo [format "reserved_for_feature_id_registers_16 = %#x" [aarch64 mrc 15 0 0 5 0]]
echo [format "reserved_for_feature_id_registers_17 = %#x" [aarch64 mrc 15 0 0 5 1]]
echo [format "reserved_for_feature_id_registers_18 = %#x" [aarch64 mrc 15 0 0 5 2]]
echo [format "reserved_for_feature_id_registers_19 = %#x" [aarch64 mrc 15 0 0 5 3]]
echo [format "reserved_for_feature_id_registers_20 = %#x" [aarch64 mrc 15 0 0 5 4]]
echo [format "reserved_for_feature_id_registers_21 = %#x" [aarch64 mrc 15 0 0 5 5]]
echo [format "reserved_for_feature_id_registers_22 = %#x" [aarch64 mrc 15 0 0 5 6]]
echo [format "reserved_for_feature_id_registers_23 = %#x" [aarch64 mrc 15 0 0 5 7]]
echo [format "reserved_for_feature_id_registers_24 = %#x" [aarch64 mrc 15 0 0 6 0]]
echo [format "reserved_for_feature_id_registers_25 = %#x" [aarch64 mrc 15 0 0 6 1]]
echo [format "reserved_for_feature_id_registers_26 = %#x" [aarch64 mrc 15 0 0 6 2]]
echo [format "reserved_for_feature_id_registers_27 = %#x" [aarch64 mrc 15 0 0 6 3]]
echo [format "reserved_for_feature_id_registers_28 = %#x" [aarch64 mrc 15 0 0 6 4]]
echo [format "reserved_for_feature_id_registers_29 = %#x" [aarch64 mrc 15 0 0 6 5]]
echo [format "reserved_for_feature_id_registers_30 = %#x" [aarch64 mrc 15 0 0 6 6]]
echo [format "reserved_for_feature_id_registers_31 = %#x" [aarch64 mrc 15 0 0 6 7]]
echo [format "reserved_for_feature_id_registers_32 = %#x" [aarch64 mrc 15 0 0 7 0]]
echo [format "reserved_for_feature_id_registers_33 = %#x" [aarch64 mrc 15 0 0 7 1]]
echo [format "reserved_for_feature_id_registers_34 = %#x" [aarch64 mrc 15 0 0 7 2]]
echo [format "reserved_for_feature_id_registers_35 = %#x" [aarch64 mrc 15 0 0 7 3]]
echo [format "reserved_for_feature_id_registers_36 = %#x" [aarch64 mrc 15 0 0 7 4]]
echo [format "reserved_for_feature_id_registers_37 = %#x" [aarch64 mrc 15 0 0 7 5]]
echo [format "reserved_for_feature_id_registers_38 = %#x" [aarch64 mrc 15 0 0 7 6]]
echo [format "reserved_for_feature_id_registers_39 = %#x" [aarch64 mrc 15 0 0 7 7]]
# Cache Size Identification
echo [format "cache_size_identification_0 = %#x" [aarch64 mrc 15 1 0 0 0]]
# Cache Level ID
echo [format "cache_level_id_0 = %#x" [aarch64 mrc 15 1 0 0 1]]
# Silicon ID
echo [format "silicon_id_0 = %#x" [aarch64 mrc 15 1 0 0 7]]
# Cache Size Selection
echo [format "cache_size_selection_0 = %#x" [aarch64 mrc 15 2 0 0 0]]
# Control
echo [format "control_0 = %#x" [aarch64 mrc 15 0 1 0 0]]
# Auxiliary Control
echo [format "auxiliary_control_0 = %#x" [aarch64 mrc 15 0 1 0 1]]
# Coprocessor Access Control
echo [format "coprocessor_access_control_0 = %#x" [aarch64 mrc 15 0 1 0 2]]
# Nonsecure Access Control
echo [format "nonsecure_access_control_0 = %#x" [aarch64 mrc 15 0 1 1 2]]
# Translation Table Base 0
echo [format "translation_table_base_0_0 = %#x" [aarch64 mrc 15 0 2 0 0]]
# Translation Table Base 1
echo [format "translation_table_base_1_0 = %#x" [aarch64 mrc 15 0 2 0 1]]
# Translation Table Base Control
echo [format "translation_table_base_control_0 = %#x" [aarch64 mrc 15 0 2 0 2]]
# Domain Access Control
echo [format "domain_access_control_0 = %#x" [aarch64 mrc 15 0 3 0 0]]
# Data Fault Status
echo [format "data_fault_status_0 = %#x" [aarch64 mrc 15 0 5 0 0]]
# Instruction Fault Status
echo [format "instruction_fault_status_0 = %#x" [aarch64 mrc 15 0 5 0 1]]
# Data Auxiliary Fault Status
echo [format "data_auxiliary_fault_status_0 = %#x" [aarch64 mrc 15 0 5 1 0]]
# Instruction Auxiliary Fault Status
echo [format "instruction_auxiliary_fault_status_0 = %#x" [aarch64 mrc 15 0 5 1 1]]
# Data Fault Address
echo [format "data_fault_address_0 = %#x" [aarch64 mrc 15 0 6 0 0]]
# Instruction Fault Address
echo [format "instruction_fault_address_0 = %#x" [aarch64 mrc 15 0 6 0 2]]
# Physical Address
echo [format "physical_address_0 = %#x" [aarch64 mrc 15 0 7 4 0]]
# Performance Monitor Control
echo [format "performance_monitor_control_0 = %#x" [aarch64 mrc 15 0 9 12 0]]
# Count Enable Set
echo [format "count_enable_set_0 = %#x" [aarch64 mrc 15 0 9 12 1]]
# Count Enable Clear
echo [format "count_enable_clear_0 = %#x" [aarch64 mrc 15 0 9 12 2]]
# Overflow Flag Status
echo [format "overflow_flag_status_0 = %#x" [aarch64 mrc 15 0 9 12 3]]
# Software Increment
#echo [format "software_increment_0 = %#x" [aarch64 mrc 15 0 9 12 4]]
# Performance Counter Selection
echo [format "performance_counter_selection_0 = %#x" [aarch64 mrc 15 0 9 12 5]]
# Cycle Count
echo [format "cycle_count_0 = %#x" [aarch64 mrc 15 0 9 13 0]]
# Event Selection
echo [format "event_selection_0 = %#x" [aarch64 mrc 15 0 9 13 1]]
# Performance Monitor Count
echo [format "performance_monitor_count_0 = %#x" [aarch64 mrc 15 0 9 13 2]]
# User Enable
echo [format "user_enable_0 = %#x" [aarch64 mrc 15 0 9 14 0]]
# Interrupt Enable Set
echo [format "interrupt_enable_set_0 = %#x" [aarch64 mrc 15 0 9 14 1]]
# Interrupt Enable Clear
echo [format "interrupt_enable_clear_0 = %#x" [aarch64 mrc 15 0 9 14 2]]
# L2 Cache Lockdown
#echo [format "l2_cache_lockdown_0 = %#x" [aarch64 mrc 15 1 9 0 0]]
# L2 Cache Auxiliary Control
echo [format "l2_cache_auxiliary_control_0 = %#x" [aarch64 mrc 15 1 9 0 2]]
# Data TLB Lockdown Register
#echo [format "data_tlb_lockdown_register_0 = %#x" [aarch64 mrc 15 0 10 0 0]]
# Instruction TLB Lockdown Register
#echo [format "instruction_tlb_lockdown_register_0 = %#x" [aarch64 mrc 15 0 10 0 1]]
# Primary Region Remap Register
echo [format "primary_region_remap_register_0 = %#x" [aarch64 mrc 15 0 10 2 0]]
# Normal Memory Remap Register
echo [format "normal_memory_remap_register_0 = %#x" [aarch64 mrc 15 0 10 2 1]]
# PLE Identification and Status
#echo [format "ple_identification_and_status_0 = %#x" [aarch64 mrc 15 0 11 0 0]]
# PLE Identification and Status
#echo [format "ple_identification_and_status_0 = %#x" [aarch64 mrc 15 0 11 0 2]]
#echo [format "ple_identification_and_status_1 = %#x" [aarch64 mrc 15 0 11 0 3]]
# PLE User Accessibility
#echo [format "ple_user_accessibility_0 = %#x" [aarch64 mrc 15 0 11 1 0]]
# PLE Channel Number
#echo [format "ple_channel_number_0 = %#x" [aarch64 mrc 15 0 11 2 0]]
# PLE Control
#echo [format "ple_control_0 = %#x" [aarch64 mrc 15 0 11 4 0]]
# PLE Internal Start Address
#echo [format "ple_internal_start_address_0 = %#x" [aarch64 mrc 15 0 11 5 0]]
# PLE Internal End Address
#echo [format "ple_internal_end_address_0 = %#x" [aarch64 mrc 15 0 11 7 0]]
# PLE Channel Status
#echo [format "ple_channel_status_0 = %#x" [aarch64 mrc 15 0 11 8 0]]
# PLE Context ID
#echo [format "ple_context_id_0 = %#x" [aarch64 mrc 15 0 11 15 0]]
# Secure or Nonsecure Vector Base Address
echo [format "secure_or_nonsecure_vector_base_address_0 = %#x" [aarch64 mrc 15 0 12 0 0]]
# Interrupt Status
echo [format "interrupt_status_0 = %#x" [aarch64 mrc 15 0 12 1 0]]
# FCSE PID
echo [format "fcse_pid_0 = %#x" [aarch64 mrc 15 0 13 0 0]]
# Context ID
echo [format "context_id_0 = %#x" [aarch64 mrc 15 0 13 0 1]]
# User read/write Thread and Process ID
echo [format "user_read/write_thread_and_process_id_0 = %#x" [aarch64 mrc 15 0 13 0 2]]
# User read-only Thread and Process ID
echo [format "user_read-only_thread_and_process_id_0 = %#x" [aarch64 mrc 15 0 13 0 3]]
# Privileged only Thread and Process ID
echo [format "privileged_only_thread_and_process_id_0 = %#x" [aarch64 mrc 15 0 13 0 4]]
log_output
