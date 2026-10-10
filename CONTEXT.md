# Devices

Words for whether a device is being heard, and for an uptime figure that has run past its sample.

## Language

**Last seen**:
The time of the last MQTT message from a device.
_Avoid_: Uptime sample, heartbeat

**Unknown**:
A device that has never been heard. A server start does not make it offline.

**Live**:
A device heard within 5 minutes, after the app has started. A fresh online, or a reading, ends offline. A saved online does not. A reading from before the offline does not.

**Stale**:
A device heard more than 5 minutes ago and not yet 15, and still in contact.

**Offline**:
A device we are not in contact with. Fifteen minutes without a message, a command that got no answer, or the word offline on its status. When the server starts, every device already heard is offline. Reloading the page does not do this. A reading from before that start does not end it. A saved online does not end it. A fresh online, or a later reading, does.
_Avoid_: Unreachable

**Old uptime**:
An uptime figure extrapolated from a sample older than 15 minutes. It does not say the device is offline.
_Avoid_: Stale, offline
