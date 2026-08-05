// Package alerts — localized alert message text (RU/EN).
//
// region MODULE_CONTRACT [DOMAIN(7): Alerting; CONCEPT(6): i18n; TECH(4): map]
// @purpose Build the DOWN/RECOVERED notification text in the operator's UI locale (stored as the
// @purpose "ui_locale" setting), so Telegram/webhook messages arrive in the language the operator
// @purpose chose in the UI, not always English.
// @io (locale, fields) -> {title, body}
// endregion MODULE_CONTRACT
// GREP_SUMMARY: locale, i18n, alert text, ru, en, down, recovered, message
package alerts

import "fmt"

// alertText returns the localized title+body for a liveness alert.
// locale defaults to English for anything other than "ru".
func alertText(locale, status, checkType string, latencyMS float64, host string) (title, body string) {
	ru := locale == "ru"
	if status == "ok" {
		if ru {
			title = fmt.Sprintf("[ВОССТАНОВЛЕНО] %s снова доступен", host)
		} else {
			title = fmt.Sprintf("[RECOVERED] %s is back up", host)
		}
	} else {
		if ru {
			title = fmt.Sprintf("[ПАДЕНИЕ] %s недоступен", host)
		} else {
			title = fmt.Sprintf("[DOWN] %s unreachable", host)
		}
	}
	if ru {
		body = fmt.Sprintf("проверка %s: статус=%s задержка=%.0fмс", checkType, status, latencyMS)
	} else {
		body = fmt.Sprintf("check %s: status=%s latency=%.0fms", checkType, status, latencyMS)
	}
	return title, body
}
