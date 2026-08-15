# Module: WordPress Ecosystem

The reference workflow — plugin/theme code is public, patches are diffable, install counts make impact measurable, and Patchstack/Wordfence/huntr pay for the work.

---

## 1. Sources

| Source | Use |
|---|---|
| `patchstack.com/database/` | earliest structured disclosure, severity, affected ranges |
| `wordfence.com/threat-intel/vulnerabilities/` + its API | corroboration, CVSS, researcher credit, often more detail |
| `wpscan.com/plugins/<slug>` | historical vuln list per plugin |
| `wordpress.org/plugins/<slug>/advanced/` | install count, active versions, changelog, close dates |
| `plugins.svn.wordpress.org/<slug>/tags/` | **every** released version, diffable — the key asset |
| plugin's GitHub repo | commits, PRs, issues, sometimes the fix before the release |

Correlation chain: Patchstack → Wordfence → CVE/NVD → plugin changelog → SVN tag diff → local lab.

---

## 2. Triage before research

```
install count      < 5k → usually not worth it unless the program lists it directly
                   > 100k → real impact, but higher duplicate pressure
auth requirement   unauthenticated ≫ subscriber ≫ contributor ≫ author ≫ admin
                   (admin-only issues are usually not vulnerabilities in WP's model —
                    admins legitimately have unfiltered_html/edit_files)
closed plugin?     removed from the directory with no fix = unpatched install base;
                   report to the vendor/program, not as an exploit drop
```
`Subscriber+ RCE` or `unauthenticated SQLi` on a 200k-install plugin is the shape that pays. `Admin stored XSS` is usually informational.

---

## 3. Version diffing

```bash
SLUG=<plugin-slug>; VULN=<x.y.z>; FIX=<x.y.z+1>
svn export -q https://plugins.svn.wordpress.org/$SLUG/tags/$VULN /tmp/$SLUG-$VULN
svn export -q https://plugins.svn.wordpress.org/$SLUG/tags/$FIX  /tmp/$SLUG-$FIX
diff -ruN /tmp/$SLUG-$VULN /tmp/$SLUG-$FIX > changes.diff
```

Then `modules/patch-analysis.md`. WordPress-specific tells in the diff:

| Added by the fix | Means the bug was |
|---|---|
| `current_user_can()` | missing authorization |
| `check_ajax_referer()` / `wp_verify_nonce()` | missing CSRF protection (+ often the real authz gap) |
| `$wpdb->prepare()` | SQL injection |
| `sanitize_*()` / `esc_*()` | injection or XSS |
| `wp_check_filetype_and_ext()` / extension allowlist | arbitrary file upload |
| `realpath()` / traversal filter | path traversal / arbitrary file read |
| `permission_callback` on `register_rest_route` | unauthenticated REST access |
| removal of `unserialize()` / `maybe_unserialize()` | PHP object injection |

---

## 4. Where the bugs live

```bash
grep -rn "wp_ajax_nopriv_" .            # unauthenticated AJAX — highest value
grep -rn "wp_ajax_" .                   # authenticated AJAX, often any-subscriber
grep -rn "register_rest_route" .        # check every permission_callback
grep -rn "admin_post_nopriv\|template_redirect\|init" . | grep -i "\$_\(GET\|POST\|REQUEST\)"
grep -rn '\$wpdb->\(query\|get_results\|get_var\|get_row\)' . | grep -v prepare
grep -rn "add_shortcode\|do_shortcode" .
grep -rn "file_get_contents\|fopen\|unlink\|move_uploaded_file\|wp_handle_upload" .
grep -rn "unserialize\|extract(\|call_user_func\|eval(\|assert(" .
grep -rn "update_option\|delete_option\|update_user_meta" .   # settings → privesc
```

`permission_callback => '__return_true'` on a REST route that changes state is a finding on its own.

---

## 5. Lab

```bash
mkdir wp-lab && cd wp-lab && cat > docker-compose.yml <<'EOF'
services:
  db:
    image: mariadb:11
    environment: [MARIADB_ROOT_PASSWORD=lab, MARIADB_DATABASE=wp,
                  MARIADB_USER=wp, MARIADB_PASSWORD=lab]
  wp:
    image: wordpress:6-php8.2
    ports: ["127.0.0.1:8080:80"]
    environment: [WORDPRESS_DB_HOST=db, WORDPRESS_DB_USER=wp,
                  WORDPRESS_DB_PASSWORD=lab, WORDPRESS_DB_NAME=wp,
                  WORDPRESS_DEBUG=1]
    volumes: ["./plugins:/var/www/html/wp-content/plugins"]
EOF
docker compose up -d
mkdir -p plugins && cp -r /tmp/$SLUG-$VULN plugins/$SLUG
# wp-cli inside the container: activate plugin, create a subscriber test user
docker compose exec wp bash -c "curl -s -o /tmp/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && php /tmp/wp-cli.phar --allow-root plugin activate $SLUG"
```
Prove the bug at the **lowest** privilege that works, then re-run against the fixed version (swap the plugin dir) for the control step.

---

## 6. Where to submit

WordPress plugin bugs rarely belong to the site's bug bounty program — they belong upstream:
- **Patchstack MVDP / Wordfence Bug Bounty** — pay for plugin/theme vulns directly, with published tiers.
- **Plugin vendor's own program** if they run one.
- The **site's** program only if the plugin is explicitly listed in scope *and* you demonstrate exploitation against their in-scope asset within policy.

Check reward tiers and duplicate policy before research — both platforms de-duplicate against pending submissions you cannot see, so freshness matters more here than anywhere else.
