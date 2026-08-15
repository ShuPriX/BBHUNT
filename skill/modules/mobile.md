# Module: Mobile (Android / iOS)

Mobile apps are usually in scope, rarely hunted, and ship their backend's secrets in the binary. Static analysis alone often produces the finding.

---

## 1. Acquire & unpack

Official store build, or the vendor's published APK/IPA. Record version and build number.

```bash
# Android
apktool d app.apk -o app_src            # resources, manifest, smali
unzip -q app.apk -d app_raw             # raw assets, libs, certs
d2j-dex2jar app.apk && jadx -d out app.apk   # readable Java
# iOS (needs a decrypted IPA from a device you own)
unzip -q app.ipa -d ipa && ls ipa/Payload/*.app
strings ipa/Payload/*.app/<binary> | less
```

Testing on a device/emulator **you own**, against the vendor's backend, is still traffic to their backend — the backend must be in scope too.

---

## 2. Static findings (highest yield, zero risk)

```bash
grep -rniE "api[_-]?key|secret|token|password|bearer |authorization" app_src/ | head -50
grep -rnE "https?://[a-z0-9.-]+" app_src/res/ | sort -u          # internal hosts, staging
find app_src -name "*.properties" -o -name "*.json" -o -name "*.plist"
```
Look for: hardcoded API keys with real scope (cloud, maps-with-billing, payment, push, analytics with admin), backend hostnames not in public DNS, staging/debug endpoints, signing/encryption keys, third-party tokens, embedded credentials for a service account.

A key is only a finding if it grants something — verify capability from documentation and, if policy permits, one benign identity call. A restricted-by-design public key is not a vulnerability.

---

## 3. Android manifest

```bash
grep -A2 "android:exported=\"true\"" app_src/AndroidManifest.xml
```
- exported Activity/Service/Receiver/Provider without permission → other apps invoke it
- exported ContentProvider with `grantUriPermissions` → arbitrary file read from the app sandbox
- `android:debuggable="true"`, `android:allowBackup="true"` in a release build
- deep links / app links with unvalidated parameters → open redirect, token theft, WebView injection
- `WebView` with `setJavaScriptEnabled(true)` + `addJavascriptInterface` + attacker-reachable URL → RCE-class in app context
- missing `usesCleartextTraffic=false`, custom TrustManager accepting all certs

## 4. iOS

Custom URL schemes and Universal Links with unvalidated input · Keychain items with weak accessibility (`kSecAttrAccessibleAlways`) · sensitive data in `NSUserDefaults`/plists/caches · `ATS` exceptions · pasteboard leakage · missing jailbreak/cert-pinning where the policy expects it (only if the program treats it as in scope).

---

## 5. Dynamic (only in scope, on your own device)

Proxy with a user-installed CA on an emulator you control. Where pinning blocks it, the bypass itself is not the finding — the API weakness behind it is.

Almost every paid mobile finding is really a **backend** finding: the app just showed you the endpoint, the parameter, or the key. Once you have the API surface, switch to `modules/api.md` — that is where the authorization bugs are.

Excluded nearly everywhere: lack of obfuscation, lack of root/jailbreak detection, lack of cert pinning as a standalone issue, tapjacking, backup of non-sensitive data, and anything requiring a rooted device plus physical access. Check `config/exclusions.yaml` before writing.
