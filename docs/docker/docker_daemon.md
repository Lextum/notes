# docker daemon

## logging
### log-driver
defines the driver you want to use. `json-file` is for local logging with builtin logrotating

### log-opts
You can define the `max-size` and the `max-file` with those options. Docker automatilicly rotates the local files. Enable `compress` so docker compresses the rotated files.

## Isolate containers with a user namespace
https://docs.docker.com/engine/security/userns-remap/
With `userns-remap` docker remaps the root user inside to docker container to a local low-priviled user.

## live-restore
https://docs.docker.com/config/containers/live-restore/

Allows container to run, even the docker daemon gets restarted. The live restore option helps reduce container downtime due to daemon crashes, planned outages, or upgrades.

## Example
```json
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "50m",
        "max-file": "10",
        "compress": "true"
    },
    "userns-remap": "default",
    "live-restore": true
}

```