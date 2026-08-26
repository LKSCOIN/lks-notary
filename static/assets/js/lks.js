/* LKSCOIN 2.0 — minimal site behaviour (no dependencies) */
(function () {
  'use strict';

  // Mobile navigation
  var toggle = document.querySelector('.nav-toggle');
  var links = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', function () {
      var open = links.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    links.addEventListener('click', function (e) {
      if (e.target.tagName === 'A') links.classList.remove('open');
    });
  }

  // Mark the current page in the navigation
  var here = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-links a[href]').forEach(function (a) {
    var target = a.getAttribute('href').split('#')[0];
    if (target && target === here) a.classList.add('active');
  });

  // Current year in the footer
  document.querySelectorAll('[data-year]').forEach(function (el) {
    el.textContent = new Date().getFullYear();
  });

  // --- Contact form -------------------------------------------------------
  // Posts to /apimail/sendmail, the mail service already running on the host
  // (nginx proxies it to 127.0.0.1:12321). Payload shape is fixed by that
  // service — see the README before changing any key below.
  //
  // These two are vestigial. lks-mail, the service behind /apimail/, ignores the
  // recipient in the request and uses the one in /etc/lks-mail/config.json —
  // deliberately, so the endpoint cannot be used to send mail to arbitrary
  // addresses. They are kept only because the payload shape expects the fields.
  // To change where enquiries go, edit the config ON THE SERVER, not here.
  var RECIPIENT = 'set-server-side';
  var SENDER = 'set-server-side';

  var form = document.getElementById('contact-form');
  var box = document.getElementById('form-status');
  var loadedAt = Math.floor(Date.now() / 1000);

  document.querySelectorAll('[data-loaded-at]').forEach(function (el) {
    el.value = loadedAt;
  });

  function status(kind, text) {
    if (!box) return;
    var colours = {
      ok: ['#1E7A54', '#E4F1E9'],
      warn: ['#96690D', '#FDF2DC'],
      error: ['#A32D2D', '#FCEBEB']
    }[kind];
    box.textContent = text;
    box.style.cssText = 'margin:0 0 18px;padding:14px 16px;border-radius:9px;' +
      'font-size:.92rem;line-height:1.5;color:' + colours[0] + ';background:' + colours[1];
  }

  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();

      var f = form.elements;
      var button = form.querySelector('button[type=submit]');

      // Honeypot: hidden from people, filled in by bots.
      if (f.website && f.website.value) { status('ok', 'Thank you — your message has been sent.'); return; }
      // Bots submit instantly; people do not.
      if (Math.floor(Date.now() / 1000) - loadedAt < 3) { status('ok', 'Thank you — your message has been sent.'); return; }

      var first = f.first_name.value.trim();
      var last = f.last_name.value.trim();
      var email = f.email.value.trim();
      var message = f.message.value.trim();

      if (!first || !last || !message || !f.privacy.checked || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        status('warn', 'Some required fields are missing or the email address is not valid. Please check and try again.');
        return;
      }

      button.disabled = true;
      status('warn', 'Sending…');

      // Payload keys are fixed by the service on port 12321 — do not rename.
      //
      // IsAsync MUST be true. Verified against the live service: with false it
      // answers `false` and sends nothing, whatever the sender address. With
      // true it returns the completed Task ({"Result":true,"Status":5}), so the
      // send has already finished by the time we get the response — the name is
      // misleading, but the behaviour is the one we want.
      var payload = {
        MailFrom: SENDER,
        MailTo: [RECIPIENT],
        MailBcc: [],
        Object: '[lkschain.io] ' + f.topic.value + ' — ' + first + ' ' + last,
        BodyMessage:
          'Name:  ' + first + ' ' + last + '\n' +
          'Email: ' + email + '\n' +
          'Type:  ' + f.topic.value + '\n\n' +
          '--- Message ---\n\n' + message,
        IsHtml: false,
        IsAsync: true
      };

      fetch(form.getAttribute('action'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
        .then(function (r) {
          return r.text().then(function (body) {
            // Surfaced in the console so a failure can be diagnosed without
            // reading the service log first.
            console.log('[lks] /apimail/sendmail →', r.status, body);

            // The service reports the outcome in the BODY, not in the status
            // code: a failed send still returns 200 with the body `false`.
            // Trusting response.ok is what made the form claim success while
            // nothing was being delivered.
            if (!r.ok) throw new Error('HTTP ' + r.status);
            var sent = false;
            try {
              var parsed = JSON.parse(body);
              sent = parsed === true || (parsed && parsed.Result === true);
            } catch (e) {
              sent = body.trim() === 'true';
            }
            if (!sent) throw new Error('the mail service rejected the message');

            status('ok', 'Thank you — your message has been sent. We reply to enquiries in the order they arrive.');
            form.reset();
          });
        })
        .catch(function (err) {
          console.error('[lks] contact form failed:', err);
          status('error', 'The message could not be sent (' + err.message + '). Please write to us directly at the address in the legal notices.');
        })
        .then(function () { button.disabled = false; });
    });
  }

  // Last-updated date on the legal page.
  // Replace this with a hardcoded date when the page is legally reviewed —
  // a legal notice should state when it was actually revised, not today.
  document.querySelectorAll('[data-legal-date]').forEach(function (el) {
    el.textContent = new Date(document.lastModified).toLocaleDateString('en-GB', {
      year: 'numeric', month: 'long', day: 'numeric'
    });
  });
})();
