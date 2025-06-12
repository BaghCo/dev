############################################################
# VARIABLES — override via terraform.tfvars or -var flags
############################################################
variable "resource_group_name" {
  type        = string
  description = "Name of the resource group for the alerts"
}

variable "location" {
  type        = string
  description = "Azure region for the scheduled-query rule resources"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Resource ID of your global Log Analytics workspace"
}

variable "action_group_id" {
  type        = string
  description = "Resource ID of the Action Group to call when an alert fires"
}

############################################################
# 1) DEFINE YOUR LOG-SEARCH ALERTS AS A LOCAL LIST
############################################################
############################################################
# Local definitions for the 11 baseline Log-search alerts
############################################################
locals {
  vm_log_alerts = [
    {
      alertRuleDescription = "High CPU usage on virtual machine"
      alertRuleDisplayName = "VM High CPU Usage"
      alertRuleName        = "VMHighCPUAlert"
      alertRuleSeverity    = 3
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Processor Information" and CounterName == "% Processor Time"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 85
      KQL
    },
    {
      alertRuleDescription = "Low available memory on virtual machine"
      alertRuleDisplayName = "VM Low Memory"
      alertRuleName        = "VMLowMemoryAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Memory" and CounterName == "% Committed Bytes In Use"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 90
      KQL
    },
    {
      alertRuleDescription = "High data disk read latency on virtual machine"
      alertRuleDisplayName = "VM High Data Disk Read Latency"
      alertRuleName        = "VMHighDataDiskReadLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Read" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer, InstanceName
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "High data disk write latency on virtual machine"
      alertRuleDisplayName = "VM High Data Disk Write Latency"
      alertRuleName        = "VMHighDataDiskWriteLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Write" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer, InstanceName
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "Low data-disk free space on virtual machine"
      alertRuleDisplayName = "VM Low Data Disk Space"
      alertRuleName        = "VMLowDataDiskSpaceAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "% Free Space" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer, InstanceName
        | where avg_CounterValue < 10
      KQL
    },
    {
      alertRuleDescription = "High OS-disk read latency on virtual machine"
      alertRuleDisplayName = "VM High OS Disk Read Latency"
      alertRuleName        = "VMHighOSDiskReadLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Read" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "High OS-disk write latency on virtual machine"
      alertRuleDisplayName = "VM High OS Disk Write Latency"
      alertRuleName        = "VMHighOSDiskWriteLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Write" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "Low OS-disk free space on virtual machine"
      alertRuleDisplayName = "VM Low OS Disk Space"
      alertRuleName        = "VMLowOSDiskSpaceAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "% Free Space" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue < 10
      KQL
    },
    {
      alertRuleDescription = "High network ingress on virtual machine"
      alertRuleDisplayName = "VM High Network In"
      alertRuleName        = "VMHighNetworkInAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Network Interface" and CounterName == "Bytes Received/sec"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 10000000
      KQL
    },
    {
      alertRuleDescription = "High network egress on virtual machine"
      alertRuleDisplayName = "VM High Network Out"
      alertRuleName        = "VMHighNetworkOutAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Network Interface" and CounterName == "Bytes Sent/sec"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 10000000
      KQL
    },
    {
      alertRuleDescription = "Agent heartbeat missing on virtual machine"
      alertRuleDisplayName = "VM Heartbeat Alert"
      alertRuleName        = "VMHeartBeatAlert"
      alertRuleSeverity    = 3
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT6H"
      query = <<-KQL
        Heartbeat
        | where TimeGenerated > ago(6h)
        | summarize Count = count() by Computer
        | where Count < 10
      KQL
    },
    # CPU percentage: warning (75%), critical (85%) — AMBA thresholds
    {
      alertRuleName         = "CpuPercentage_Warning"
      alertRuleDisplayName  = "VM CPU % Warning"
      alertRuleDescription  = "CPU > 75% over 15 minutes"
      alertRuleSeverity     = 3
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Processor" and Name=="UtilizationPercentage"
        | summarize AvgVal=avg(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where AvgVal > 75
      KQL
    },
    {
      alertRuleName         = "CpuPercentage_Critical"
      alertRuleDisplayName  = "VM CPU % Critical"
      alertRuleDescription  = "CPU > 85% over 15 minutes"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Processor" and Name=="UtilizationPercentage"
        | summarize AvgVal=avg(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where AvgVal > 85
      KQL
    },

    # Available Memory Bytes: threshold < 1GB — AMBA threshold
    {
      alertRuleName         = "AvailableMemoryBytes"
      alertRuleDisplayName  = "VM Available Memory Bytes"
      alertRuleDescription  = "Available Memory Bytes < 1GB"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Memory" and Name=="AvailableMB"
        | summarize AvgMB=avg(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where AvgMB < 1024
      KQL
    },

    # Data Disk Free Space % <10%
    {
      alertRuleName         = "DataDiskFreeSpace"
      alertRuleDisplayName  = "VM Data Disk % Free Space"
      alertRuleDescription  = "Data Disk % Free Space < 10%"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="FreeSpacePercentage"
        | extend Tags=parse_json(Tags)
        | summarize AvgVal=avg(Val) by bin(TimeGenerated,5m), Computer, InstanceName, _ResourceId
        | where AvgVal < 10
      KQL
    },

    # OS Disk Free Space % <10%
    {
      alertRuleName         = "OsDiskFreeSpace"
      alertRuleDisplayName  = "VM OS Disk % Free Space"
      alertRuleDescription  = "OS Disk % Free Space < 10%"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="FreeSpacePercentage"
        | extend Tags=parse_json(Tags)
        | where InstanceName=="C:"
        | summarize AvgVal=avg(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where AvgVal < 10
      KQL
    },

    # Network In Total > 10MB
    {
      alertRuleName         = "NetworkInTotal"
      alertRuleDisplayName  = "VM Network In Total"
      alertRuleDescription  = "Network In Total bytes > 10MB over 5 min"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT5M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Network" and Name=="NetworkInTotal"
        | summarize SumVal=sum(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where SumVal > 10000000
      KQL
    },

    # Network Out Total > 10MB
    {
      alertRuleName         = "NetworkOutTotal"
      alertRuleDisplayName  = "VM Network Out Total"
      alertRuleDescription  = "Network Out Total bytes > 10MB over 5 min"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT5M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Network" and Name=="NetworkOutTotal"
        | summarize SumVal=sum(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where SumVal > 10000000
      KQL
    },

    # Inbound Flows > 1000 (default)
    {
      alertRuleName         = "InboundFlows"
      alertRuleDisplayName  = "VM Inbound Flows"
      alertRuleDescription  = "Inbound flows > 1000 (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT5M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Network" and Name=="InboundFlows"
        | summarize MaxVal=max(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where MaxVal > 1000
      KQL
    },
    {
      alertRuleName         = "OutboundFlows"
      alertRuleDisplayName  = "VM Outbound Flows"
      alertRuleDescription  = "Outbound flows > 1000 (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT5M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Network" and Name=="OutboundFlows"
        | summarize MaxVal=max(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where MaxVal > 1000
      KQL
    },

    # Disk Read Bytes > 10MB (default)
    {
      alertRuleName         = "DiskReadBytes"
      alertRuleDisplayName  = "VM Disk Read Bytes"
      alertRuleDescription  = "Disk Read Bytes > 10MB over 5 min (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT5M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="ReadBytes"
        | summarize SumVal=sum(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where SumVal > 10000000
      KQL
    },
    {
      alertRuleName         = "DiskWriteBytes"
      alertRuleDisplayName  = "VM Disk Write Bytes"
      alertRuleDescription  = "Disk Write Bytes > 10MB over 5 min (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT5M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="WriteBytes"
        | summarize SumVal=sum(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where SumVal > 10000000
      KQL
    },

    # IOPS % and Queue Depth defaults (default thresholds)
    {
      alertRuleName         = "DataDiskIOPSConsumedPercentage"
      alertRuleDisplayName  = "VM Data Disk % IOPS Consumed"
      alertRuleDescription  = "Data Disk % IOPS Consumed > 80% (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="IOPSConsumedPercentage"
        | summarize AvgVal=avg(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where AvgVal > 80
      KQL
    },
    {
      alertRuleName         = "OsDiskIOPSConsumedPercentage"
      alertRuleDisplayName  = "VM OS Disk % IOPS Consumed"
      alertRuleDescription  = "OS Disk % IOPS Consumed > 80% (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="IOPSConsumedPercentage"
        | extend Tags=parse_json(Tags)
        | where InstanceName=="C:"
        | summarize AvgVal=avg(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where AvgVal > 80
      KQL
    },
    {
      alertRuleName         = "DataDiskQueueDepth"
      alertRuleDisplayName  = "VM Data Disk Queue Depth"
      alertRuleDescription  = "Data Disk Queue Depth > 1000 (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="QueueDepth"
        | summarize MaxVal=max(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where MaxVal > 1000
      KQL
    },
    {
      alertRuleName         = "OsDiskQueueDepth"
      alertRuleDisplayName  = "VM OS Disk Queue Depth"
      alertRuleDescription  = "OS Disk Queue Depth > 1000 (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="QueueDepth"
        | extend Tags=parse_json(Tags)
        | where InstanceName=="C:"
        | summarize MaxVal=max(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where MaxVal > 1000
      KQL
    },

    # Disk operations per second defaults >1000
    {
      alertRuleName         = "DataDiskReadOpsPerSec"
      alertRuleDisplayName  = "VM Data Disk Read Ops/sec"
      alertRuleDescription  = "Data Disk Read Ops/sec > 1000 (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="ReadOperationsPerSecond"
        | summarize SumVal=sum(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where SumVal > 1000
      KQL
    },
    {
      alertRuleName         = "OsDiskWriteOpsPerSec"
      alertRuleDisplayName  = "VM OS Disk Write Ops/sec"
      alertRuleDescription  = "OS Disk Write Ops/sec > 1000 (default)"
      alertRuleSeverity     = 2
      evaluationFrequency   = "PT5M"
      windowSize            = "PT15M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="LogicalDisk" and Name=="WriteOperationsPerSecond"
        | extend Tags=parse_json(Tags)
        | where InstanceName=="C:"
        | summarize SumVal=sum(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where SumVal > 1000
      KQL
    },

    # VM Availability metric <1 = VM down (AMBA pattern)
    {
      alertRuleName         = "VmAvailabilityDown"
      alertRuleDisplayName  = "VM Availability Down"
      alertRuleDescription  = "VmAvailabilityMetric <1 - VM down"
      alertRuleSeverity     = 3
      evaluationFrequency   = "PT5M"
      windowSize            = "PT5M"
      autoMitigate          = true
      query = <<-KQL
        InsightsMetrics
        | where Namespace=="Computer" and Name=="Availability"
        | summarize MinVal=min(Val) by bin(TimeGenerated,5m), Computer, _ResourceId
        | where MinVal < 1
      KQL
    },
  ]
}

############################################################
# Generate one azurerm_monitor_scheduled_query_rules_alert_v2
# for each baseline log-search alert
############################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "vm_log" {
  for_each            = { for r in local.vm_log_alerts : r.alertRuleName => r }
  name                = each.value.alertRuleName
  resource_group_name = var.resource_group_name
  location            = var.location

  description   = each.value.alertRuleDescription
  display_name  = each.value.alertRuleDisplayName
  severity      = each.value.alertRuleSeverity
  enabled       = true
  auto_mitigate = each.value.autoMitigate
  frequency     = each.value.evaluationFrequency
  window_size   = each.value.windowSize

  criteria {
    query            = each.value.query
    time_aggregation = "Count"
  }

  action {
    azurerm_action_group_id = var.action_group_id
  }
}
