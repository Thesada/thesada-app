// Super-admin pairing flow. Issues per-device
// mTLS client certs signed by the internal CA and pushes them to the device
// via MQTT CLI (cert.set + cert.apply). All handlers here assume the
// authmw.RequireSuperAdmin wrap.
package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/service"
)

// dynsecDeviceRoleName returns the dynsec role name for a paired device.
// Mirrors the TLS CN format so the role is trivially discoverable from the
// broker's perspective (use_identity_as_username maps CN -> username, and
// the client keyed on that username carries this role).
// in: tenant slug, device id. out: role name.
func dynsecDeviceRoleName(tenant, deviceID string) string {
	return fmt.Sprintf("device-%s-%s", tenant, deviceID)
}

// dynsecSettingCrossTenantRead is the per-tenant settings key that controls
// whether paired devices get broad subscribe access across the tenant tree.
// When true: broad subscribe + receive on the ENTIRE thesada/# tree across
// every tenant. Default ON for the "default" tenant (homelab, legacy 3-tier
// layout where CYD reads OWB, OLED reads sht31, Spotify state, etc), OFF
// for any other tenant - multi-tenant isolation stays tight unless an
// operator opts in per tenant. Flipped via SettingsService at runtime.
const dynsecSettingCrossTenantRead = "mqtt_cross_tenant_read"

// dynsecDeviceACLs returns the per-device ACL set for a paired device.
//
// Publish scope is always narrow: the device can only send on its own
// `thesada/<prefix>/#` plus the shared `homeassistant/#` discovery tree.
// Tenant isolation on the write path is enforced here regardless of any
// subscribe-side policy.
//
// Subscribe scope depends on the `mqtt_cross_tenant_read` per-tenant
// setting:
//   - broadRead=true  -> read on `thesada/#` so display devices can consume
//     other devices' sensor topics (CYD dashboard reading OWB/sht31,
//     Spotify state from HA, etc). Default for the `default` tenant.
//   - broadRead=false -> tenant-scoped read only (`thesada/<tenant>/#`).
//     Default for every non-default tenant.
//
// HA discovery topics (`homeassistant/#`) are readable in both modes
// because HA lives outside the tenant tree and is one-per-deployment.
// in: tenant id, topic prefix, broad-read flag. out: ACL list.
func dynsecDeviceACLs(tenantID, topicPrefix string, broadRead bool) []mqtt.DynsecACL {
	ownTopic := topicPrefix + "/#"
	acls := make([]mqtt.DynsecACL, 0, 6)
	acls = append(acls,
		// Publish within own prefix only.
		mqtt.DynsecACL{ACLType: "publishClientSend", Topic: ownTopic, Allow: true},
		// Publish HA discovery retained configs.
		mqtt.DynsecACL{ACLType: "publishClientSend", Topic: "homeassistant/#", Allow: true},
		// HA state + discovery retained topics readable always.
		mqtt.DynsecACL{ACLType: "subscribePattern", Topic: "homeassistant/#", Allow: true},
		mqtt.DynsecACL{ACLType: "publishClientReceive", Topic: "homeassistant/#", Allow: true},
	)
	var subTopic string
	if broadRead {
		subTopic = "thesada/#"
	} else {
		subTopic = "thesada/" + tenantID + "/#"
	}
	acls = append(acls,
		mqtt.DynsecACL{ACLType: "subscribePattern", Topic: subTopic, Allow: true},
		mqtt.DynsecACL{ACLType: "publishClientReceive", Topic: subTopic, Allow: true},
	)
	return acls
}

// deviceCertValidity is the lifetime of a device client cert. Short enough
// to limit blast radius if a device is compromised, long enough to avoid
// fleet-wide re-pair churn. Re-issue is a one-click operation on this page.
const deviceCertValidity = 365 * 24 * time.Hour

// mTLS / password broker ports. Broker hostname is unchanged; only the
// port swaps so HAProxy can route to the matching mosquitto listener
// (1883 password, 1884 mTLS). See infrastructure docs/sop-mqtt-mtls.md.
const (
	mqttPortMTLS     = 8884
	mqttPortPassword = 8883
)

// adminPairRow is the view-model for one row on the pairing page.
type adminPairRow struct {
	Device service.Device
	Cert   *service.DeviceCertificate
	Status string // "unpaired" | "paired"
}

// handleAdminCACert serves the CA certificate PEM as a downloadable file.
// Operators need this to configure the Mosquitto cert listener.
// in: writer, request. out: ca.crt attachment.
func (s *Server) handleAdminCACert(w http.ResponseWriter, _ *http.Request) {
	if s.ca == nil {
		http.Error(w, "CA not initialized", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="thesada-ca.crt"`)
	_, _ = w.Write([]byte(s.ca.CertPEMString()))
}

// handleAdminDevicePairIndex renders the super-admin pairing page: every
// device cross-tenant with pair status, active cert metadata, and an
// issue-or-revoke action.
// in: writer, request. out: HTML page.
func (s *Server) handleAdminDevicePairIndex(w http.ResponseWriter, r *http.Request) {
	devices, err := s.services.Devices.ListAllForAdmin(r.Context())
	if err != nil {
		slog.Error("admin pair device list failed", "err", err)
		http.Error(w, "device list failed", http.StatusInternalServerError)
		return
	}
	rows := make([]adminPairRow, 0, len(devices))
	for _, d := range devices {
		cert, cerr := s.services.Certificates.GetActive(r.Context(), d.TenantID, d.ID)
		if cerr != nil {
			slog.Warn("pair page: cert lookup failed", "device", d.ID, "err", cerr)
		}
		status := "unpaired"
		if cert != nil {
			status = "paired"
		}
		rows = append(rows, adminPairRow{Device: d, Cert: cert, Status: status})
	}
	// Unpaired first so operators land on what still needs work.
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].Status == "unpaired" && rows[j].Status != "unpaired"
	})
	s.render(w, r, "admin-devices-pair.html", map[string]interface{}{
		"Rows":     rows,
		"Flash":    r.URL.Query().Get("ok"),
		"FlashErr": r.URL.Query().Get("error"),
		"CAReady":  s.ca != nil,
	})
}

// handleAdminDevicePairIssue signs a per-device cert with the CA, persists
// via CertificateService, then pushes client_cert + client_key via MQTT CLI
// cert.set and triggers cert.apply. Atomic: on any failure mid-flow the
// operator can re-click to retry (Issue writes a new cert row, revoking
// any prior one implicitly via the Revoke action, and firmware tolerates
// re-set).
// in: writer, POST /admin/devices/{id}/pair/issue. out: 302 to pair page.
func (s *Server) handleAdminDevicePairIssue(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil || device == nil {
		http.NotFound(w, r)
		return
	}
	if s.ca == nil {
		http.Redirect(w, r, "/admin/devices/pair?error=CA+not+initialized", http.StatusFound)
		return
	}

	cn := fmt.Sprintf("thesada-%s-%s", device.TenantID, device.DeviceID)
	certPEM, keyPEM, serialHex, err := s.ca.SignDeviceCert(cn, deviceCertValidity)
	if err != nil {
		slog.Error("sign device cert failed", "device", device.ID, "cn", cn, "err", err)
		http.Redirect(w, r, "/admin/devices/pair?error=sign+failed", http.StatusFound)
		return
	}

	topicPrefix := s.deviceTopicPrefix(device)
	user := authmw.CurrentUser(r)

	// Push-first, persist-last. If any MQTT step fails we do NOT mark the
	// device paired in the db, so the UI state always reflects what the
	// device actually has in NVS.
	//
	// Order keeps the device in a valid auth state the whole time:
	//   1. cert.set client_cert - NVS half-written, hasClientCert() stays false -> password auth
	//   2. cert.set client_key  - NVS complete, but port still 8883 -> cert sits dormant
	//   3. config.set mqtt.port 8884 - stored, not active until next reconnect
	//   4. CertificateService.Issue - persist + flip paired_at (only now)
	//   5. config.reload - best-effort reconnect on mTLS listener
	if msg, ok := s.pushCertPart(r.Context(), topicPrefix, "client_cert", certPEM); !ok {
		slog.Error("push client_cert failed", "device", device.ID, "err", msg)
		http.Redirect(w, r, "/admin/devices/pair?error="+msg, http.StatusFound)
		return
	}
	if msg, ok := s.pushCertPart(r.Context(), topicPrefix, "client_key", keyPEM); !ok {
		slog.Error("push client_key failed", "device", device.ID, "err", msg)
		http.Redirect(w, r, "/admin/devices/pair?error="+msg, http.StatusFound)
		return
	}
	if msg, ok := s.runCLI(r.Context(), topicPrefix, "config.set",
		fmt.Sprintf("mqtt.port %d", mqttPortMTLS)); !ok {
		slog.Error("config.set mqtt.port failed", "device", device.ID, "err", msg)
		http.Redirect(w, r, "/admin/devices/pair?error="+msg, http.StatusFound)
		return
	}

	// Provision the dynsec role + client before persist. Role-first so the
	// client create can attach it atomically. "already exists" is tolerated
	// for retry safety: a prior pair attempt that succeeded here but failed
	// on Issue should be resumable.
	dynsecCtx, dynsecCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer dynsecCancel()
	roleName := dynsecDeviceRoleName(device.TenantID, device.DeviceID)
	// Per-tenant broad-read policy. Default ON for "default" (homelab with
	// legacy 3-tier topics where dashboards read across all devices), OFF
	// for every other tenant. Operators can flip via SettingsService.
	broadRead := s.services.Settings.GetBool(device.TenantID,
		dynsecSettingCrossTenantRead, device.TenantID == "default")
	if err := s.mqtt.CreateDynsecRole(dynsecCtx, roleName, dynsecDeviceACLs(device.TenantID, topicPrefix, broadRead)); err != nil && !mqtt.IsDynsecAlreadyExists(err) {
		slog.Error("dynsec createRole failed", "device", device.ID, "role", roleName, "err", err)
		http.Redirect(w, r, "/admin/devices/pair?error=dynsec+role+create+failed", http.StatusFound)
		return
	}
	// Cert-only client: empty password, auth via TLS CN on the mTLS listener.
	if err := s.mqtt.CreateDynsecClient(dynsecCtx, cn, "", []string{roleName}); err != nil && !mqtt.IsDynsecAlreadyExists(err) {
		slog.Error("dynsec createClient failed", "device", device.ID, "cn", cn, "err", err)
		http.Redirect(w, r, "/admin/devices/pair?error=dynsec+client+create+failed", http.StatusFound)
		return
	}

	now := time.Now()
	if err := s.services.Certificates.Issue(r.Context(), device.TenantID, device.ID, serialHex, cn, now, now.Add(deviceCertValidity), certPEM); err != nil {
		slog.Error("persist device cert failed", "device", device.ID, "err", err)
		http.Redirect(w, r, "/admin/devices/pair?error=persist+failed", http.StatusFound)
		return
	}

	// cli/restart instead of config.reload: config.reload's networkChanged
	// diff is always false here because firmware's config.set already
	// refreshes the in-memory config (Shell.cpp:818 Config::load()), so
	// the subsequent config.reload reads oldPort==newPort and skips the
	// reconnect path. Restart is atomic - boot reads fresh config.json
	// (port=8884) + NVS cert -> mTLS engages on first connect. Mirrors
	// the device-delete cascade pattern in preemptiveCertClear. Best-
	// effort fire-and-forget: device reboots before any response.
	restartTopic := topicPrefix + "/cli/restart"
	if perr := s.mqtt.PublishRaw(restartTopic, []byte("{}"), 0, false); perr != nil {
		slog.Warn("pair issue: cli/restart publish failed",
			"device", device.ID, "topic", restartTopic, "err", perr)
	} else {
		slog.Info("pair issue: cli/restart published",
			"device", device.ID, "topic", restartTopic)
	}

	logPairStateChange(device, "unpaired", "paired", user.Email, "pair_issue")

	http.Redirect(w, r, "/admin/devices/pair?ok=paired+"+device.DeviceID, http.StatusFound)
}

// pushCertPart sends one cert.set call with the "<type>\n<PEM>" payload and
// waits for the device cli/response. Returns (status_query_param, ok).
// in: ctx, topic prefix, part type ("client_cert"|"client_key"), PEM text.
// out: user-facing short message (if !ok), ok flag.
func (s *Server) pushCertPart(ctx context.Context, topicPrefix, partType, pem string) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	payload := make([]byte, 0, len(partType)+1+len(pem))
	payload = append(payload, []byte(partType)...)
	payload = append(payload, '\n')
	payload = append(payload, []byte(pem)...)

	resp, err := s.mqtt.CLIRequestRaw(cctx, topicPrefix, "cert.set", payload)
	if err != nil {
		return "push+" + partType + "+failed+(device+unreachable)", false
	}
	if !resp.OK {
		return "device+rejected+" + partType, false
	}
	return "", true
}

// runCLI is a short helper for text-payload CLI commands that stay online
// (config.set, restart-free ops). Returns a user-facing query string on
// failure + an ok flag; empty string + true on success.
// in: ctx, topic prefix, command, payload. out: message, ok.
func (s *Server) runCLI(ctx context.Context, topicPrefix, command, payload string) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.mqtt.CLIRequest(cctx, topicPrefix, command, payload)
	if err != nil {
		return command + "+failed+(device+unreachable)", false
	}
	if !resp.OK {
		return "device+rejected+" + command, false
	}
	return "", true
}

// handleAdminDevicePairRevoke marks the active cert as revoked in the db
// and best-effort pushes cert.clear to the device. Server-side revocation
// happens unconditionally - the device may be offline, but the paired_at
// flag and the revoked row guarantee the broker can enforce revocation
// once CRL/OCSP is wired up.
// in: writer, POST /admin/devices/{id}/pair/revoke. out: 302 to pair page.
func (s *Server) handleAdminDevicePairRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil || device == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.services.Certificates.Revoke(r.Context(), device.TenantID, device.ID); err != nil {
		slog.Error("revoke device cert failed", "device", device.ID, "err", err)
		http.Redirect(w, r, "/admin/devices/pair?error=revoke+failed", http.StatusFound)
		return
	}

	// Best-effort transition the online device into password-mode recovery
	// state before tearing down broker-side dynsec. The old sequence here
	// (config.set + cert.clear + config.reload waiting for acks in order)
	// was racy: cert.clear fires _onCertClearedHook which drops MQTT
	// before config.reload can apply the new port, and the watchdog reboot
	// took 15-30min. preemptiveCertClear publishes config.set + cert.clear
	// + restart as spaced fire-and-forget instead, matching the device-
	// delete cascade pattern shipped 2026-04-30. Same physical effect,
	// no ordering race, recovery in ~10s.
	preemptiveCertClear(r.Context(), s, device, "revoke")

	// Tear down dynsec client + role so the broker refuses the old CN even
	// if the cert somehow re-appears in NVS. Role delete is best-effort -
	// a failure here is logged but does not block the revoke since the
	// cert revocation in the db is already done.
	cn := fmt.Sprintf("thesada-%s-%s", device.TenantID, device.DeviceID)
	roleName := dynsecDeviceRoleName(device.TenantID, device.DeviceID)
	dynsecCtx, dynsecCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer dynsecCancel()
	if derr := s.mqtt.DeleteDynsecClient(dynsecCtx, cn); derr != nil {
		slog.Warn("dynsec deleteClient failed", "device", device.ID, "cn", cn, "err", derr)
	}
	if derr := s.mqtt.DeleteDynsecRole(dynsecCtx, roleName); derr != nil {
		slog.Warn("dynsec deleteRole failed", "device", device.ID, "role", roleName, "err", derr)
	}

	user := authmw.CurrentUser(r)
	if device.PairedAt != nil {
		logPairStateChange(device, "paired", "revoked", user.Email, "admin_revoke")
	}
	http.Redirect(w, r, "/admin/devices/pair?ok=revoked+"+device.DeviceID, http.StatusFound)
}

// logPairStateChange emits the device pairing audit edge
// (device.pair.state_change) in one consistent shape across the issue, revoke,
// and delete paths. from/to are "unpaired" | "paired" | "revoked"; reason names
// the trigger (e.g. "pair_issue", "admin_revoke", "device_delete"). Serial / CN
// / validity live on the persisted cert row, so the edge log stays lean.
// in: device, prior state, next state, operator email, reason. out: none.
func logPairStateChange(device *service.Device, from, to, actor, reason string) {
	slog.Info("device.pair.state_change",
		"from", from, "to", to,
		"device", device.DeviceID, "tenant", device.TenantID,
		"user", actor, "reason", reason)
}
