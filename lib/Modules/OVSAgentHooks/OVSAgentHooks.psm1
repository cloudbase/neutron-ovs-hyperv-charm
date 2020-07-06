# Copyright 2014-2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

Import-Module JujuWindowsUtils
Import-Module JujuHooks
Import-Module JujuLogging
Import-Module JujuUtils
Import-Module HyperVNetworking
Import-Module OVSCharmUtils
Import-Module JujuHelper
Import-Module OpenStackCommon

# function New-ExeServiceWrapper {
#     $neutronPluginContext = Get-NeutronPluginContext
#     if (!$neutronPluginContext.Count) {
#         $installDir = $NOVA_INSTALL_DIR
#     } else {
#         $installDir = $neutronPluginContext["install-location"]
#     }

#     $pythonDir = Get-PythonDir -InstallDir $installDir
#     $python = Join-Path $pythonDir "python.exe"
#     $updateWrapper = Join-Path $pythonDir "Scripts\UpdateWrappers.py"

#     $cmd = @($python, $updateWrapper, "neutron-openvswitch-agent = neutron.cmd.eventlet.plugins.ovs_neutron_agent:main")
#     Invoke-JujuCommand -Command $cmd
# }

function Start-ConfigureVMSwitch {
    $vmSwitchName = Get-JujuVMSwitchName

    [array]$dataPorts = Get-OVSDataPorts
    # TODO (gsamfira): Look into vmswitch teaming
    $dataPort = $dataPorts[0]
    $vmSwitches = [array](Get-VMSwitch -SwitchType External -ErrorAction SilentlyContinue)
    foreach ($i in $vmSwitches) {
        if ($i.NetAdapterInterfaceDescription -eq $dataPort.InterfaceDescription) {
            $agentRestart = $false
            if($i.Name -ne $vmSwitchName) {
                $agentRestart = $true
                Rename-VMSwitch $i -NewName $vmSwitchName | Out-Null
            }
            if($agentRestart) {
                $status = (Get-Service -Name $OVS_VSWITCHD_SERVICE_NAME).Status
                if($status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                    Restart-Service $OVS_VSWITCHD_SERVICE_NAME -Force
                }
            }
            return
        }
    }
    $vmSwitch = Get-JujuVMSwitch
    if($vmSwitch) {
        # VMSwitch was already created but it has the wrong port. We just change it.
        Set-VMSwitch -VMSwitch $vmSwitch -NetAdapterName $dataPort.Name -Confirm:$false
        return
    }
    Write-JujuWarning "Adding new vmswitch: $vmSwitchName"
    New-VMSwitch -Name $vmSwitchName -NetAdapterName $dataPort.Name -AllowManagementOS $false | Out-Null
    if ($managementOS) {
        Rename-NetAdapter -Name "vEthernet ($vmSwitchName)" -NewName $vmSwitchName
    }
}

function Get-NeutronServiceName {
    <#
    .SYNOPSIS
    Returns the neutron service name.
    #>

    $charmServices = Get-CharmServices
    return $charmServices['neutron-ovs']['service']
}

function New-CharmServices {
    $charmServices = Get-CharmServices
    $neutronSvc = $charmServices['neutron-ovs']

    $agent = Get-Service $neutronSvc["service"] -ErrorAction SilentlyContinue
    if (!$agent) {
        New-Service -Name $neutronSvc["service"] `
                    -BinaryPathName $neutronSvc["serviceBinPath"] `
                    -DisplayName $neutronSvc["display_name"] -Confirm:$false
        Start-ExternalCommand { sc.exe failure $neutronSvc["service"] reset=5 actions=restart/1000 }
        Start-ExternalCommand { sc.exe failureflag $neutronSvc["service"] 1 }
        Stop-Service $neutronSvc["service"]
    }
}

function Start-ConfigureNeutronAgent {
    Install-OVS
    Start-ConfigureVMSwitch
    Enable-OVSExtension
    New-OVSInternalInterfaces
}

function Restart-Neutron {
    $serviceName = Get-NeutronServiceName
    $status = (Get-Service -Name $OVS_VSWITCHD_SERVICE_NAME).Status
    if($status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
        Stop-Service -Force $OVS_VSWITCHD_SERVICE_NAME | Out-Null
        Start-Service $OVS_VSWITCHD_SERVICE_NAME
    }
    Stop-Service $serviceName
    Start-Service $serviceName
}

function Get-CharmServices {
    $neutronPluginContext = Get-NeutronPluginContext
    if (!$neutronPluginContext.Count) {
        $distro = $DEFAULT_OPENSTACK_VERSION
        $installDir = $NOVA_INSTALL_DIR 
    } else {
        $distro = $neutronPluginContext["openstack-version"]
        $installDir = $neutronPluginContext["install-location"]
    }

    $neutronOVSConf = Join-Path $installDir "etc\neutron_ovs_agent.conf"
    $serviceWrapperNeutron = Get-ServiceWrapper -Service "Neutron" -InstallDir $installDir
    $pythonDir = Get-PythonDir -InstallDir $installDir
    $neutronOVSAgentExe = Join-Path $pythonDir "Scripts\neutron-openvswitch-agent.exe"
    $jujuCharmServices = @{
        "neutron-ovs" = @{
            "template" = "$distro/neutron_ovs_agent"
            "service" = $NEUTRON_OVS_AGENT_SERVICE_NAME
            "binpath" = "$neutronOVSAgentExe"
            "serviceBinPath" = "`"$serviceWrapperNeutron`" neutron-openvswitch-agent `"$neutronOVSAgentExe`" --config-file `"$neutronOVSConf`""
            "config" = "$neutronOVSConf"
            "display_name" = "Neutron Open vSwitch Agent"
            "context_generators" = @(
                @{
                    "generator" = (Get-Item "function:Get-RabbitMQContext").ScriptBlock
                    "relation" = "amqp"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-CharmConfigContext").ScriptBlock
                    "relation" = "config"
                    "mandatory" = $true
                },
                # @{
                #     "generator" = (Get-Item "function:Get-SystemContext").ScriptBlock
                #     "relation" = "system"
                #     "mandatory" = $true
                # },
                @{
                    "generator" = (Get-Item "function:Get-NeutronApiContext").ScriptBlock
                    "relation" = "neutron-plugin-api"
                    "mandatory" = $true
                }
            )
        }
    }
    return $jujuCharmServices
}

function Get-NeutronPluginContext {
    $required = @{
        "openstack-version" = $null
        "install-location" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation 'neutron-plugin-api' -RequiredContext $required
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}

function Get-NeutronApiContext {
    Write-JujuWarning "Generating context for neutron-api"
    $cfg = Get-JujuCharmConfig
    $required = @{
        "overlay-network-type" = $null
        "l2-population" = $null
        "neutron-api-ready" = $null
        "neutron-security-groups" = $null
        "service_host" = $null
        "service_password" = $null
        "service_port" = $null
        "service_protocol" = $null
        "service_tenant" = $null
        "service_username" = $null
        "auth_host" = $null
        "auth_port" = $null
        "auth_protocol" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation 'neutron-plugin-api' -RequiredContext $required
    if(!$ctxt.Count) {
        return @{}
    }
    if($cfg["disable_security_groups"]) {
        $ctxt["neutron-security-groups"] = $false
    }
    $ctxt["tunnel_types"] = $ctxt['overlay-network-type']
    $ctxt["l2_population"] = $ctxt["l2-population"]
    $ctxt["local_ip"] = Get-OVSLocalIP

    $ctxt["enable_security_group"] = $ctxt['neutron-security-groups']
    return $ctxt
}

# function Get-SystemContext {
#     # TODO: Populate this with relevant context
#     # $ovsDBSockFile = Join-Path $env:ProgramData "openvswitch\db.sock"
#     $ctxt = @{
#         # "install_dir" = "$NOVA_INSTALL_DIR"
#         # "force_config_drive" = "False"
#         # "config_drive_inject_password" = "False"
#         # "config_drive_cdrom" = "False"
#         # "vmswitch_name" = Get-JujuVMSwitchName
#         # "my_ip" = Get-JujuUnitPrivateIP
#         # "lock_dir" = "$NOVA_DEFAULT_LOCK_DIR"
#         # "ovs_db_sock_file" = "$ovsDBSockFile"
#     }
#     return $ctxt
# }

function Get-CharmConfigContext {
    $ctxt = Get-ConfigContext
    if(!$ctxt['log_dir']) {
        $ctxt['log_dir'] = "$NOVA_DEFAULT_LOG_DIR"
    }
  
    if (!(Test-Path $ctxt['log_dir'])) {
        New-Item -ItemType Directory -Path $ctxt['log_dir']
    }

    if($ctxt['ssl_ca']) {
        $ca_file = Join-Path $NOVA_INSTALL_DIR "etc\openvswitch-ca.pem"
        Write-FileFromBase64 -Content $ctxt['ssl_ca'] -File $ca_file
        $ctxt['ssl_ca_file'] = $ca_file
    }
    return $ctxt
}

function Set-HyperVUniqueMACAddressesPool {
    $registryNamespace = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization"
    $randomBytes = @(
        [byte](Get-Random -Minimum 0 -Maximum 255),
        [byte](Get-Random -Minimum 0 -Maximum 255)
    )
    # Generate unique pool of MAC addresses
    $minMacAddress = @(0x00, 0x15, 0x5D, $randomBytes[0], $randomBytes[1], 0x00)
    Set-ItemProperty -Path $registryNamespace -Name "MinimumMacAddress" -Value ([byte[]]$minMacAddress)
    $maxMacAddress = @(0x00, 0x15, 0x5D, $randomBytes[0], $randomBytes[1], 0xff)
    Set-ItemProperty -Path $registryNamespace -Name "MaximumMacAddress" -Value ([byte[]]$maxMacAddress)
}

function Set-CharmUnitStatus {
    Param(
        [array]$IncompleteRelations=@()
    )

    if(!$IncompleteRelations.Count) {
        $msg = "Unit is ready"
        Set-JujuStatus -Status active -Message $msg
        return
    }
    $IncompleteRelations = $IncompleteRelations | Select-Object -Unique
    $msg = "Incomplete relations: {0}" -f @($IncompleteRelations -join ', ')
    Set-JujuStatus -Status blocked -Message $msg
}

function Invoke-InstallHook {
    Set-HyperVUniqueMACAddressesPool
    Install-OVS
    # New-ExeServiceWrapper
}

function Invoke-StopHook {
    Disable-OVS
    Uninstall-OVS
    Remove-CharmState -Namespace "novahyperv" -Key "ovs_adapters_info"

    $vmSwitch = Get-JujuVMSwitch
    if($vmSwitch) {
        $vmSwitch | Remove-VMSwitch -Force -Confirm:$false
    }
}

function Set-NeutronPluginContext {
    $vmSwitch = Get-JujuVMSwitch
    if (!$vmSwitch) {
        Write-JujuWarning "VMswitch not present. Delaying neutron-plugin context"
        return
    }
    $relationSettings = @{
        "vswitch-name" = $vmSwitch.Name
        "neutron-service-name" = $NEUTRON_OVS_AGENT_SERVICE_NAME
    }
    Write-JujuWarning ("Relation data is {0}" -f @((ConvertTo-Json $relationSettings)))
    $rids = Get-JujuRelationIds -Relation "neutron-plugin"
    foreach ($rid in $rids){
        Set-JujuRelation -RelationId $rid -Settings $relationSettings
    }
}

function Invoke-ConfigChangedHook {
    New-CharmServices
    Start-ConfigureNeutronAgent

    $incompleteRelations = @()
    $services = Get-CharmServices

    $contextGenerators = $services['neutron-ovs']['context_generators']
    $template = $services['neutron-ovs']['template']
    $configFile = $services['neutron-ovs']['config']

    $neutronIncompleteRelations = New-ConfigFile -ContextGenerators $contextGenerators `
                                                 -Template $template `
                                                 -OutFile $configFile
    if (!$neutronIncompleteRelations.Count) {
        Write-JujuWarning "Restarting service Neutron"
        Restart-Neutron
        Set-NeutronPluginContext
    } else {
        $incompleteRelations += $neutronIncompleteRelations
    }
    Set-CharmUnitStatus -IncompleteRelations $incompleteRelations
}

function Invoke-AMQPRelationJoinedHook {
    $username, $vhost = Get-RabbitMQConfig
    $relationSettings = @{
        'username' = $username
        'vhost' = $vhost
    }
    $rids = Get-JujuRelationIds -Relation "amqp"
    foreach ($rid in $rids){
        Set-JujuRelation -RelationId $rid -Settings $relationSettings
    }
}
