package web

import (
	"fmt"
	"net/url"
)

// Device-page flash messages. Redirects carry a code, never text, so a
// crafted link cannot put words on the page. A code only exists as a
// deviceFlashCode, which registers its text when declared, so a handler
// cannot redirect with a code the page does not know.

// deviceFlashCode is one registered redirect code: its query key ("ok" or
// "error") and the code value.
type deviceFlashCode struct{ key, code string }

var deviceFlashText = map[string]map[string]string{"ok": {}, "error": {}}

var (
	flashSensorCleared = deviceFlashOK("sensor_cleared", "Sensor telemetry cleared.")
	flashRevoked       = deviceFlashOK("revoked",
		"Revoked. The device was told to drop its certificate. Current firmware reboots within seconds. An older build waits for its next restart. Then it can be claimed again with the code on its sticker.")

	flashMetricRequired     = deviceFlashErr("metric_required", "Pick a metric to delete.")
	flashConfirmMetric      = deviceFlashErr("confirm_metric", "The confirmation did not match the metric.")
	flashSensorDeleteFailed = deviceFlashErr("sensor_delete_failed", "Deleting the telemetry failed.")
	flashConfirmDeviceID    = deviceFlashErr("confirm_device_id", "Type the device id to confirm the revoke.")
	flashRevokeFailed       = deviceFlashErr("revoke_failed", "Revoke failed, nothing was changed.")
	flashRevokeCertFailed   = deviceFlashErr("revoke_cert_failed",
		"Enrollment was reopened, but the certificate could not be revoked. Try again.")
	flashRevokeNoOwner = deviceFlashErr("revoke_no_owner",
		"This device has no owner. Revoke it from Admin > Pair devices.")
	flashRevokeNotHeld = deviceFlashErr("revoke_not_held",
		"This device has been claimed again since, so it can no longer be revoked from here.")
	flashRevokeAlready = deviceFlashErr("revoke_already",
		"This device is already revoked. If it still holds its old certificate, clear it on the device to re-enroll.")
	flashRevokeUnsent = deviceFlashErr("revoke_unsent",
		"Revoked, but the device was not told. It keeps its old certificate and cannot re-enroll until it drops it.")
)

// deviceFlashOK registers a success code. in: code, page text. out: code handle.
func deviceFlashOK(code, text string) deviceFlashCode { return registerDeviceFlash("ok", code, text) }

// deviceFlashErr registers an error code. in: code, page text. out: code handle.
func deviceFlashErr(code, text string) deviceFlashCode {
	return registerDeviceFlash("error", code, text)
}

// registerDeviceFlash panics on a duplicate so two texts never share a code.
// in: query key, code, page text. out: code handle.
func registerDeviceFlash(key, code, text string) deviceFlashCode {
	if _, dup := deviceFlashText[key][code]; dup {
		panic(fmt.Sprintf("device flash %s=%s registered twice", key, code))
	}
	deviceFlashText[key][code] = text
	return deviceFlashCode{key: key, code: code}
}

// on builds the redirect target carrying this code. in: page path. out: URL.
func (f deviceFlashCode) on(path string) string {
	return path + "?" + f.key + "=" + url.QueryEscape(f.code)
}

// deviceFlash maps a request's codes to page text; unknown codes render nothing.
// in: query values. out: ok text, error text.
func deviceFlash(q url.Values) (string, string) {
	return deviceFlashText["ok"][q.Get("ok")], deviceFlashText["error"][q.Get("error")]
}
