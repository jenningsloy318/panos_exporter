panos_exporter
---
panos_exporter is an exporter to scape metrics from Paloalto NGFW api to get its current status and expose as prometheus metrics; and it can be used to montior its running statuss 


create a example configuration as yaml file:
```yaml
devices:
    10.36.48.15:
      username: user
      password: pass
```

then start panos_exporter via 
```sh
panos_exporter --config.file=panos_exporter.yaml 
```

then we can get the metrics via 
```
curl http://<panos_exporter host>:9654/panos?target=10.36.48.15

```

## prometheus job conf
add panos_exporter job conif as following
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

## Support devices
- PA-3220(8.1.7)
