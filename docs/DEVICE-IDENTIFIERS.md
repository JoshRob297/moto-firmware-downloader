# Device identifiers: IMEI vs serial number

MFD accepts either an **IMEI** (cellular devices) or a **serial number** (WiFi-only
tablets and devices without a modem, e.g. Lenovo `TB310FU`).

```bash
mfd imei XT2435-1 351234567890123              # IMEI (14-15 digits)
mfd imei TB310FU HA1ABCDEFG                    # serial (alphanumeric, 6-32 chars)
mfd imei TB310FU 1234567890 --serial           # force serial interpretation
```

The wizard accepts both and reports which one it detected.

---

## How the official client does it

The mapping below comes from the shipped client, not from guesswork. Extracted from
**Software Fix (Rescue and Smart Assistant) v7.4.3.4**
(`software_fix_v7.4.3.4_setup.exe`, 139 MB, published `download.lenovo.com`):

| Plugin / binary | Relevant strings |
|---|---|
| `lenovo.mbg.service.lmsa.flash.dll` | `/rescueDevice/getNewResource.jhtml`, `/rescueDevice/getNewResourceByImei.jhtml`, `/rescueDevice/getNewResourceBySN.jhtml`, `imei`, `serialno`, `modelName`, `marketName`, `roCarrier`, `sku` |
| `lenovo.mbg.service.common.webservices.dll` | endpoint table (`/dictionary/getApiInfo.jhtml`, `/common/rsa.jhtml`, `/device/getDeviceInfo.jhtml`, `/rescueDevice/getParamType.jhtml`, `/rescueDevice/getMarketSupport.jhtml`, `/rescueDevice/smartMarketNames.jhtml`, `/rescueDevice/getRescueModelRecipe.jhtml`, ...) |
| `AdbWinApi.dll` | `serialNumber` (the client reads the serial from the device over ADB) |

So the official tool picks the endpoint by identifier type:

| Device | Endpoint | Request field |
|---|---|---|
| Cellular (has IMEI) | `/rescueDevice/getNewResourceByImei.jhtml` | `imei` |
| WiFi-only (serial only) | `/rescueDevice/getNewResourceBySN.jhtml` | `serialno` |
| Server-resolved | `/rescueDevice/getNewResource.jhtml` | generic |

MFD mirrors that: same endpoints, same field names, `sku`/`carrierSku` set to the
model code, plus `encryptCode` and `roCarrier` as before.

---

## Verification status

* **`getNewResourceByImei.jhtml`** - confirmed working against the live API
  (`HTTP 200 code 0000`).
* **`getNewResourceBySN.jhtml`** - present in the official client, **not yet
  confirmed against the live API**. Reason: without a session every route answers
  `410 Missing device fingerprint.` (the gate runs before routing), and a
  nonexistent route is only distinguishable when authenticated (it returns a Spring
  `404`). Verifying it requires a session.
  Until then, MFD calls `getNewResourceBySN.jhtml` and transparently falls back to
  `getNewResource.jhtml` if the former does not answer with an LMSA payload. When
  the fallback is used, the diagnostic line reports the endpoint that answered.
* **`getMarketSupport.jhtml` / `smartMarketNames.jhtml`** - present in the official
  client; not yet wired into MFD. They are the candidate answer for models whose
  firmware is published under a market that MFD's default carrier list does not
  query.

---

## Diagnostics

When nothing is found, MFD prints the last catalog response verbatim:

```text
[i] Last catalog response: endpoint=/rescueDevice/getNewResourceBySN.jhtml code=1000 desc=Request error content=null romResource.uri=false
```

Meaning of the fields:

* `content=null` / `content=undefined` - the API answered but returned no build.
* `content=array[N]` with `romResource.uri=false` - builds were returned but without a
  downloadable resource.
* `endpoint=...` - which route produced that answer, useful to tell the serial path
  apart from the IMEI path.

---

## Known gaps

* Tablet lookups (`TB310FU`) are implemented but unverified against the server; see
  above.
* Models whose firmware lives under a market outside MFD's default carrier list
  (reported case: `XT1900-1`) need `getMarketSupport.jhtml` discovery, which is not
  implemented yet.
