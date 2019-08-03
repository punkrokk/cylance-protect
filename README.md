# Cylance Optics Integration Pack

Integration for Cylance Optics.

## Configuration

Create a configuration file `/opt/stackstorm/configs/cylance_optics.yaml`:

```
    ---
    app_id: 
    app_secret: 
    tenant_value: 

```

* ``app_id`` - Cylance App Id 
* ``app_secret`` - Cylance Application Secret Key
* ``tenant_value`` - Cylance Tenant Value


Add the following to the file `/etc/st2/st2.conf`

```
    [packs]
    enable_common_libs = True
```

## Actions

| Action | Description|
|---|---|
| ``cylance_add_hash`` | Add a hash to Cylance Quarantine
| ``cylance_change_policy`` | Change policy of a specific device
| ``cylance_get_device`` | Get Device Detail from Cylance
| ``cylance_get_threat`` | Get Threat Detail from Cylance
| ``cylance_get_threat_url`` | Get Threat URL from Cylance
| ``cylance_get_threat_devices`` | Get Threat Device Detail from Cylance
| ``cylance_remove_hash`` | Remove a hash from Cylance Quarantine
