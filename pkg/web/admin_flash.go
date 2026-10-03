package web

import (
	"fmt"
	"net/url"
)

// Admin flash messages. Redirects carry a code, never text, so a crafted
// link cannot put words on an admin page. Same shape as the device page.

type adminFlashCode struct{ key, code string }

var adminFlashText = map[string]map[string]string{"ok": {}, "error": {}}

var (
	flashAdminReassigned      = adminFlashOK("reassigned", "Device reassigned.")
	flashAdminBulkReassigned  = adminFlashOK("bulk_reassigned", "Reassign finished.")
	flashAdminBulkReassignMix = adminFlashOK("bulk_reassigned_partial", "Reassign finished. Some devices failed. Counts are in the log.")
	flashAdminOTA             = adminFlashOK("ota_dispatched", "OTA check dispatched.")
	flashAdminOTAMix          = adminFlashOK("ota_dispatched_partial", "OTA check dispatched. Some devices failed. Counts are in the log.")
	flashAdminDeleted         = adminFlashOK("deleted", "Device deleted.")
	flashAdminBulkDeleted     = adminFlashOK("bulk_deleted", "Delete finished.")
	flashAdminBulkDeletedMix  = adminFlashOK("bulk_deleted_partial", "Delete finished. Some devices failed. Counts are in the log.")
	flashPairPaired           = adminFlashOK("paired", "Paired. The device was told to restart.")
	flashPairRevoked          = adminFlashOK("pair_revoked", "Revoked.")
	flashSecretSet            = adminFlashOK("secret_set", "Secret stored.")
	flashSecretCleared        = adminFlashOK("secret_cleared", "Override cleared. The device keeps the old value until the next provision.")
	flashSecretProvisioned    = adminFlashOK("provisioned", "Provisioned.")
	flashSecretProvisionedMix = adminFlashOK("provisioned_partial", "Provisioned. Some fields were skipped. Counts are in the log.")
	flashTenantDefaultSet     = adminFlashOK("default_set", "Default stored.")
	flashTenantDefaultPending = adminFlashOK("default_set_pending", "Default stored. Devices that inherit it still need provisioning.")
	flashTenantWifiSet        = adminFlashOK("wifi_default_set", "WiFi default stored.")
	flashTenantCleared        = adminFlashOK("default_cleared", "Default cleared. Devices keep the old value until the next provision.")
	flashTenantPushed         = adminFlashOK("pushed", "Push finished.")
	flashTenantPushedMix      = adminFlashOK("pushed_partial", "Push finished with devices unreachable, rejected, or skipped. Counts are in the log.")

	flashAdminUnknownTenant   = adminFlashErr("unknown_tenant", "Unknown tenant.")
	flashAdminReassignFailed  = adminFlashErr("reassign_failed", "Reassign failed. That device id may already exist in the target tenant.")
	flashAdminConfirmDevice   = adminFlashErr("confirm_device_id", "Type the device id to confirm.")
	flashAdminRevokeFailed    = adminFlashErr("revoke_failed", "Revoke failed.")
	flashAdminDeleteFailed    = adminFlashErr("delete_failed", "Delete failed.")
	flashAdminEnrollReset     = adminFlashErr("enroll_reset_failed", "Deleted, but enrollment reset failed. Re-enrollment stays blocked.")
	flashAdminUnknownAction   = adminFlashErr("unknown_action", "Unknown bulk action.")
	flashAdminNoneSelected    = adminFlashErr("none_selected", "No devices selected.")
	flashAdminNoneResolvable  = adminFlashErr("none_resolvable", "None of the selected devices could be found.")
	flashAdminCrossTenant     = adminFlashErr("cross_tenant", "That selection spans tenants. Confirm the cross-tenant action to continue.")
	flashAdminBulkRefused     = adminFlashErr("bulk_refused", "Some paired devices were refused because the fallback path is not usable. Tick accept serial recovery to delete them anyway.")
	flashAdminBulkSealed      = adminFlashErr("bulk_sealed", "Some devices were deleted, but enrollment reset failed. Re-enrollment stays blocked.")
	flashAdminBulkBoth        = adminFlashErr("bulk_refused_sealed", "Some paired devices were refused, and some deletes left enrollment sealed. Counts are in the log.")
	flashAdminRecoveryRefused = adminFlashErr("recovery_refused", "Refused. The fallback path is not usable. Tick accept serial recovery to continue anyway.")
	flashPairCA               = adminFlashErr("ca_missing", "CA is not initialized.")
	flashPairSign             = adminFlashErr("sign_failed", "Could not sign a certificate.")
	flashPairPersist          = adminFlashErr("persist_failed", "Could not store the certificate.")
	flashPairPushCert         = adminFlashErr("push_cert_failed", "The device did not accept the certificate.")
	flashPairPushKey          = adminFlashErr("push_key_failed", "The device did not accept the key.")
	flashPairPort             = adminFlashErr("port_failed", "Could not set the MQTT port on the device.")
	flashPairDynsec           = adminFlashErr("dynsec_failed", "Broker setup failed.")
	flashPairActivate         = adminFlashErr("activate_failed", "The certificate was pushed but could not be marked active.")
	flashPairRevokeFailed     = adminFlashErr("pair_revoke_failed", "Revoke failed.")
	flashPairEnrollReset      = adminFlashErr("pair_enroll_reset_failed", "Revoked, but enrollment reset failed. Re-enrollment stays blocked.")
	flashSecretDisabled       = adminFlashErr("secrets_disabled", "Device secrets are disabled.")
	flashSecretFieldValue     = adminFlashErr("field_and_value", "Field and value are required.")
	flashSecretSSID           = adminFlashErr("ssid_and_password", "SSID and password are required.")
	flashSecretSetFailed      = adminFlashErr("set_failed", "Could not store that secret.")
	flashSecretField          = adminFlashErr("field_required", "Pick a field.")
	flashSecretClearFailed    = adminFlashErr("clear_failed", "Clear failed.")
	flashSecretNoOverride     = adminFlashErr("no_override", "There is no override to clear.")
	flashSecretNoDefault      = adminFlashErr("no_default", "There is no default to clear.")
	flashSecretDecrypt        = adminFlashErr("secret_decrypt_failed", "Could not read a device secret.")
	flashSecretRejected       = adminFlashErr("secret_rejected", "The device rejected a secret.")
	flashSecretUnreachable    = adminFlashErr("secret_unreachable", "The device could not be reached to set a secret.")
	flashSecretPush           = adminFlashErr("secret_push_failed", "Could not push a secret to the device.")
	flashTenantCountUnknown   = adminFlashErr("inheritor_unknown", "The default was stored, but the device count is unknown. Run Push to devices.")
	flashTenantDecrypt        = adminFlashErr("decrypt_failed", "Could not read that default.")
	flashTenantNoneSet        = adminFlashErr("no_default_set", "No default is set for that field.")
	flashTenantTargets        = adminFlashErr("target_lookup_failed", "Could not list the devices that inherit this default.")
)

func adminFlashOK(code, text string) adminFlashCode { return registerAdminFlash("ok", code, text) }

func adminFlashErr(code, text string) adminFlashCode {
	return registerAdminFlash("error", code, text)
}

func registerAdminFlash(key, code, text string) adminFlashCode {
	if _, dup := adminFlashText[key][code]; dup {
		panic(fmt.Sprintf("admin flash %s=%s registered twice", key, code))
	}
	adminFlashText[key][code] = text
	return adminFlashCode{key: key, code: code}
}

// query is the code as a query pair, without the leading ?.
// in: receiver. out: key=code.
func (f adminFlashCode) query() string {
	return f.key + "=" + url.QueryEscape(f.code)
}

// on builds the redirect target carrying this code. in: page path. out: URL.
func (f adminFlashCode) on(path string) string {
	return path + "?" + f.query()
}

// adminFlash maps a request's codes to page text. Unknown codes render nothing.
// in: query values. out: ok text, error text.
func adminFlash(q url.Values) (string, string) {
	return adminFlashText["ok"][q.Get("ok")], adminFlashText["error"][q.Get("error")]
}

// secretAbortFlash maps a provision abort token to a registered code.
// The token is an internal string, never request text.
// in: abort token. out: error code.
func secretAbortFlash(msg string) adminFlashCode {
	switch msg {
	case "secret+decrypt+failed":
		return flashSecretDecrypt
	case "device+rejected+secret":
		return flashSecretRejected
	case "push+secret+failed+(device+unreachable)":
		return flashSecretUnreachable
	default:
		return flashSecretPush
	}
}
