Panos_exporter
---
panos_exporter is an exporter to scape metrics from Paloalto NGFW api to get its current status and expose as prometheus metrics; and it can be used to montior its running statuss 

### Run from binary

Create an example configuration as yaml file:
```yaml
devices:
    10.36.48.15:
      username: user
      password: pass
```

Then start panos_exporter via 
```sh
panos_exporter --config.file=panos_exporter.yaml 
```

Then you can get the metrics via the following command (the IP address beeing the Palo Alto appliance to monitor):
```sh
curl http://<panos_exporter host>:9654/panos?target=10.36.48.15
```

### Run with Docker

Run Panos exporter as a container by providing the configuration file with a bind mount (`-v <local file>:<container file>`).
To access the metrics, you may bind the container port to your host port (`-p <host_port>:<container_port>`).

```shell
docker run \
    -v $(pwd)/panos_exporter.yaml:/panos_exporter.yaml \
    -p 9654:9654 \
    ghcr.io/jenningsloy318/panos_exporter:latest \
    --config.file=/panos_exporter.yaml
```



## Prometheus Configuration
add panos_exporter job config as following
  ```yaml
    - job_name: 'panos_exporter'
      metrics_path: /panos
      # scheme defaults to 'http'.

      static_configs:
      - targets:
        - 10.36.48.15
      relabel_configs:
        - source_labels: [__address__]
          target_label: __param_target
        - source_labels: [__param_target]
          target_label: instance
        - target_label: __address__
          replacement: localhost:9654  ### the address of the panos_exporter address

  ```
## API Commands for metrics
- global_counter_collector: `<show><counter><global></global></counter></show>`
- session_collector: `<show><session><info></info></session></show>`
- interface_collector: `<show><interface>all</interface></show>`
- interface_counter_collector: `<show><counter><interface>all</interface></counter></show>`
- system_resource_utilization_collector: `<show><system><resources></resources></system></show>`
- data_processor_resource_utilization_collector: `<show><running><resource-monitor><second><last>1</last></second></resource-monitor></running></show>`
- report_collector:
  - Top blocked websites: `type=report&reporttype=predefined&reportname=top-blocked-websites`
  - Top sources: `type=report&reporttype=predefined&reportname=top-sources`
  - Top destinations: `type=report&reporttype=predefined&reportname=top-destinations`
- panorama_collector (specific to panorama instances):
  - Security rules usage for each device group: `<show><rule-hit-count><device-group><entry name='{deviceGroup}'><pre-rulebase><entry name='security'><rules><all/></rules></entry></pre-rulebase></entry></device-group></rule-hit-count></show>`
  - NAT rules usage for each device group: `<show><rule-hit-count><device-group><entry name='{deviceGroup}'><pre-rulebase><entry name='nat'><rules><all/></rules></entry></pre-rulebase></entry></device-group></rule-hit-count></show>`

## Support devices
- PA-3220(8.1.7)
