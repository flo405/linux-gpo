# Policy Schemas (MVP)

Only three kinds exist:

## PolkitPolicy
```yaml
apiVersion: lgpo.io/v1
kind: PolkitPolicy
metadata: { name: <slug> }
selector: { tags: { group: ["laptops"] } }
spec:
  rules:
    - name: <rule-name>
      matches:
        - action_id: <exact-id> | action_prefix: <prefix>
      subject: { active: true|false, group: <grp>, user: <user> }
      result: YES|NO|AUTH_ADMIN|AUTH_ADMIN_KEEP
      default_result: NO   # only used with action_prefix
```

## DconfPolicy
```yaml
apiVersion: lgpo.io/v1
kind: DconfPolicy
metadata: { name: <slug> }
selector: { tags: { group: ["laptops"] } }
spec:
  settings:
    <schema/key>:
      <key>: "<literal or typed e.g. uint32 300>"
  locks:
    - /schema/key/subkey
```

## ModprobePolicy
```yaml
apiVersion: lgpo.io/v1
kind: ModprobePolicy
metadata: { name: <slug> }
selector: { tags: { group: ["laptops"] } }
spec:
  blacklist: ["usb_storage", "uas"]
  installFalse: false
  updateInitramfs: true
```
