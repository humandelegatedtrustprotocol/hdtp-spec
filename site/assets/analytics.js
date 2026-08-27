/* PACT site telemetry.
 *
 * One track() call fans out to whichever backends are configured at build time:
 * GA4 (GA_MEASUREMENT_ID) and/or Mixpanel (MIXPANEL_TOKEN). If neither is set the build
 * omits this file's config and every call here is a no-op, so the site stays clean.
 *
 * What is collected is described in the site footer. Keep the two in sync.
 */
(function () {
  'use strict'

  // Global Privacy Control / Do Not Track are honoured. Set to false to collect regardless
  // (check your obligations for your audience before you do).
  var HONOR_GPC = true

  var cfg = window.PACT_ANALYTICS || {}
  var page = window.PACT_PAGE || { id: 'unknown', title: document.title }

  var optedOut = HONOR_GPC && (
    navigator.globalPrivacyControl === true ||
    navigator.doNotTrack === '1' || window.doNotTrack === '1'
  )

  // Consent. A stored choice always wins; with nothing stored the default is ON, so
  // this is a notice with an opt-out rather than prior opt-in. GPC/DNT sits ABOVE it
  // as a hard override: a browser that asks not to be tracked is never shown a banner,
  // because there is nothing for it to consent to.
  var CONSENT_KEY = 'pact_analytics_consent'
  var DEFAULT_ON = true

  function readConsent () {
    try { return localStorage.getItem(CONSENT_KEY) } catch (e) { return null }
  }
  function writeConsent (v) {
    try { localStorage.setItem(CONSENT_KEY, v) } catch (e) {}
  }

  var configured = Boolean(cfg.ga || cfg.mixpanel)
  var choice = readConsent()
  var enabled = configured && !optedOut &&
    (choice === 'granted' || (choice === null && DEFAULT_ON))

  /* ------------------------------------------------------------- backends */

  window.dataLayer = window.dataLayer || []
  function gtag () { window.dataLayer.push(arguments) }

  if (enabled && cfg.ga) {
    gtag('js', new Date())
    // send_page_view is off so the page_view below carries the same custom params as
    // every other event, which keeps the whole stream queryable the same way.
    gtag('config', cfg.ga, { send_page_view: false })
  }

  var mp = null
  if (enabled && cfg.mixpanel && window.mixpanel) {
    try {
      window.mixpanel.init(cfg.mixpanel, {
        track_pageview: false,
        persistence: 'localStorage',
        ignore_dnt: false,
        // EU-residency project: the default ingest host is US and would drop these events.
        api_host: 'https://api-eu.mixpanel.com',
        // Mixpanel's own autocapture ($-prefixed events) runs ALONGSIDE the curated
        // events below, which carry section dwell and scroll depth that autocapture
        // does not produce. Two page-view sources, distinguishable by the $ prefix.
        autocapture: true,
        // Session replay for every visit. Gated by `enabled` above, so GPC/DNT still
        // switches it off. Keep the footer disclosure in build.mjs in sync with this.
        record_sessions_percent: 100,
      })
      mp = window.mixpanel
    } catch (e) { mp = null }
  }

  var t0 = Date.now()

  function base () {
    return {
      page_id: page.id,
      page_title: page.title,
      page_path: location.pathname,
      since_load_ms: Date.now() - t0,
      viewport_w: window.innerWidth,
      viewport_h: window.innerHeight,
    }
  }

  function track (name, props, opts) {
    if (!enabled) return
    var payload = Object.assign(base(), props || {})
    var final = (opts && opts.final) === true
    if (cfg.ga) {
      gtag('event', name, final ? Object.assign({ transport_type: 'beacon' }, payload) : payload)
    }
    if (mp) {
      try { mp.track(name, payload, final ? { transport: 'sendBeacon' } : undefined) } catch (e) {}
    }
  }

  /* ------------------------------------------------------------ page view */

  track('page_view', {
    referrer: document.referrer || '(none)',
    screen_w: screen.width,
    screen_h: screen.height,
    theme: document.documentElement.getAttribute('data-theme') ||
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'system-dark' : 'system-light'),
  })

  /* --------------------------------------------------------- scroll depth */

  var marks = [25, 50, 75, 90, 100]
  var hit = {}
  var maxDepth = 0

  function docHeight () {
    return Math.max(1, document.documentElement.scrollHeight - window.innerHeight)
  }

  function onScroll () {
    var pct = Math.min(100, Math.round((window.scrollY / docHeight()) * 100))
    if (pct > maxDepth) maxDepth = pct
    for (var i = 0; i < marks.length; i++) {
      var m = marks[i]
      if (pct >= m && !hit[m]) {
        hit[m] = true
        track('scroll_depth', { depth_pct: m })
      }
    }
  }

  var scrollTick = false
  window.addEventListener('scroll', function () {
    if (scrollTick) return
    scrollTick = true
    requestAnimationFrame(function () { scrollTick = false; onScroll() })
  }, { passive: true })
  onScroll()

  /* -------------------------------------------------------- engaged time */

  var engagedMs = 0
  var lastTick = Date.now()
  var idle = false
  var idleTimer = null

  function markActive () {
    idle = false
    clearTimeout(idleTimer)
    idleTimer = setTimeout(function () { idle = true }, 30000)
  }
  ;['mousemove', 'keydown', 'scroll', 'click', 'touchstart'].forEach(function (ev) {
    window.addEventListener(ev, markActive, { passive: true })
  })
  markActive()

  setInterval(function () {
    var now = Date.now()
    if (!document.hidden && !idle) engagedMs += now - lastTick
    lastTick = now
  }, 1000)

  var heartbeats = 0
  setInterval(function () {
    if (document.hidden || idle) return
    heartbeats++
    track('engaged_heartbeat', { engaged_ms: engagedMs, beat: heartbeats, scroll_pct: maxDepth })
  }, 15000)

  /* ------------------------------------------------- section impressions */

  var seen = {}
  var enteredAt = {}
  var sectionCount = 0

  function observeSections (nodes) {
    if (!enabled || !('IntersectionObserver' in window)) return
    sectionCount = nodes.length

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var el = entry.target
        var id = el.getAttribute('data-section-id') || '(unknown)'
        var title = el.getAttribute('data-section-title') || id
        var index = Number(el.getAttribute('data-section-index') || 0)

        if (entry.isIntersecting) {
          if (enteredAt[id] === undefined) enteredAt[id] = Date.now()
          if (!seen[id]) {
            // Confirm it stayed in view — guards against fast scroll-through counting as a read.
            var at = enteredAt[id]
            setTimeout(function () {
              if (seen[id] || enteredAt[id] !== at) return
              seen[id] = true
              track('section_impression', {
                section_id: id,
                section_title: title,
                section_index: index,
                section_total: sectionCount,
              })
            }, 1000)
          }
        } else if (enteredAt[id] !== undefined) {
          var dwell = Date.now() - enteredAt[id]
          enteredAt[id] = undefined
          if (dwell >= 1000) {
            track('section_dwell', {
              section_id: id,
              section_title: title,
              section_index: index,
              dwell_ms: dwell,
            })
          }
        }
      })
    }, { threshold: [0.5] })

    nodes.forEach(function (n) { io.observe(n) })
  }

  /* -------------------------------------------------------------- clicks */

  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a')
    if (!a) return

    if (a.dataset.toc) {
      track('toc_click', { target_id: a.dataset.toc, target_title: a.textContent.trim() })
      return
    }
    if (a.dataset.cta) {
      track('cta_click', { cta: a.dataset.cta, label: a.textContent.trim() })
      return
    }
    if (a.classList.contains('anchor')) {
      var h = a.closest('h2, h3')
      track('heading_link_click', { heading_id: h ? h.id : '(none)' })
      return
    }
    var href = a.getAttribute('href') || ''
    if (/^https?:/i.test(href) && a.hostname !== location.hostname) {
      track('outbound_click', { href: href, host: a.hostname, label: a.textContent.trim().slice(0, 80) })
    }
  }, true)

  document.addEventListener('copy', function () {
    var sel = String(window.getSelection() || '')
    if (sel.length < 2) return
    track('text_copy', { chars: sel.length })
  })

  window.addEventListener('beforeprint', function () {
    track('print', { scroll_pct: maxDepth })
  })

  /* ---------------------------------------------------------- session end */

  var ended = false
  function endSession (reason) {
    if (ended) return
    ended = true
    track('session_end', {
      reason: reason,
      max_scroll_pct: maxDepth,
      engaged_ms: engagedMs,
      total_ms: Date.now() - t0,
      sections_seen: Object.keys(seen).length,
      sections_total: sectionCount,
    }, { final: true })
  }

  window.addEventListener('pagehide', function () { endSession('pagehide') })
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') endSession('hidden')
  })

  /* ---------------------------------------------------------------- api */

  /* ------------------------------------------------------------- consent ui */

  // The bundle is same-origin (build.mjs vendors it), so having it on the page sends
  // nothing anywhere. Processing starts at mixpanel.init, which is gated on `enabled`
  // above — so turning analytics off here is a real stop, not a cosmetic one.
  function turnOff () {
    writeConsent('denied')
    enabled = false
    window.pact.enabled = false
    if (cfg.ga) { window['ga-disable-' + cfg.ga] = true }
    if (mp) {
      // Stops the session recorder and drops the stored identifiers, not just future events.
      try { mp.stop_session_recording() } catch (e) {}
      try { mp.opt_out_tracking({ clear_persistence: true }) } catch (e) {}
    }
    syncNotice()
  }

  // Re-initialising Mixpanel mid-page after an opt-out leaves half-torn-down state, so
  // switching back on reloads instead. Cheap on a static document site.
  function turnOn () {
    writeConsent('granted')
    if (!enabled) location.reload()
  }

  // The footer paragraph is rendered at build time and asserts active recording. Once
  // someone turns analytics off it is a false statement, so it gets rewritten to match
  // the live state — the same rule the build-time gating follows.
  function syncNotice () {
    var n = document.querySelector('[data-pact-notice]')
    if (!n || enabled) return
    n.textContent = optedOut
      ? 'Your browser sends Global Privacy Control or Do Not Track, so this site records ' +
        'nothing about your visit.'
      : 'Analytics and session replay are off for this browser. This site records nothing ' +
        'about your visit.'
  }

  var panel = null
  function closePanel () {
    if (panel) { panel.remove(); panel = null }
  }

  function openPanel () {
    if (!configured || panel) return
    panel = document.createElement('div')
    panel.className = 'consent'
    panel.setAttribute('role', 'dialog')
    panel.setAttribute('aria-label', 'Analytics settings')

    var box = document.createElement('div')
    box.className = 'consent-in'

    var msg = document.createElement('p')
    msg.className = 'consent-msg'
    if (optedOut) {
      msg.textContent = 'Your browser sends Global Privacy Control or Do Not Track, ' +
        'so analytics and session replay are off for this visit. Nothing is recorded.'
    } else if (enabled) {
      msg.textContent = 'This site records how the spec gets read — pages, sections, ' +
        'scroll depth, clicks — and replays visits to show where readers get stuck. ' +
        'It is on by default. There are no accounts, forms or search here, so nothing ' +
        'you type is collected.'
    } else {
      msg.textContent = 'Analytics and session replay are off for this browser. ' +
        'Nothing about your visit is recorded.'
    }
    box.appendChild(msg)

    var acts = document.createElement('div')
    acts.className = 'consent-act'

    if (!optedOut) {
      var toggle = document.createElement('button')
      toggle.type = 'button'
      toggle.className = 'consent-btn'
      toggle.textContent = enabled ? 'Turn off' : 'Turn on'
      toggle.addEventListener('click', function () {
        if (enabled) { turnOff(); closePanel(); openPanel() } else { turnOn() }
      })
      acts.appendChild(toggle)
    }

    var done = document.createElement('button')
    done.type = 'button'
    done.className = 'consent-btn primary'
    done.textContent = 'Done'
    done.addEventListener('click', function () {
      // Closing is itself an answer, otherwise the banner nags on every visit.
      if (!optedOut) writeConsent(enabled ? 'granted' : 'denied')
      closePanel()
    })
    acts.appendChild(done)

    box.appendChild(acts)
    panel.appendChild(box)
    document.body.appendChild(panel)
    done.focus()
  }

  // Footer control, so the choice stays reachable after the banner is dismissed.
  document.addEventListener('click', function (e) {
    var t = e.target.closest && e.target.closest('[data-pact-consent]')
    if (t) { e.preventDefault(); panel ? closePanel() : openPanel() }
  })

  syncNotice()

  // First visit only, and never when the browser already said no.
  if (configured && !optedOut && choice === null) openPanel()

  /* ---------------------------------------------------------------- api */

  window.pact = {
    track: track,
    observeSections: observeSections,
    enabled: enabled,
    optedOut: optedOut,
    openConsent: openPanel,
    setConsent: function (on) { on ? turnOn() : turnOff() },
  }
})()
