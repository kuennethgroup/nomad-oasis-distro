(function () {
  "use strict";

  const restrictionCode = "email_domain_not_authorized";
  const fallbackUrl = "/access-restricted";
  let redirecting = false;

  function redirectIfRestricted(status, body) {
    if (redirecting || status !== 403 || !body) {
      return;
    }

    const detail = body.detail;
    if (!detail || detail.code !== restrictionCode) {
      return;
    }

    redirecting = true;
    window.location.replace(detail.restriction_url || fallbackUrl);
  }

  async function inspectFetchResponse(response) {
    if (response.status !== 403) {
      return;
    }
    try {
      redirectIfRestricted(response.status, await response.clone().json());
    } catch (_error) {
      // A non-JSON 403 belongs to another authorization rule.
    }
  }

  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = async function () {
      const response = await originalFetch.apply(this, arguments);
      void inspectFetchResponse(response);
      return response;
    };
  }

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (_method, url) {
    this.__nomadAccessPolicyUrl = url;
    return originalOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function () {
    this.addEventListener("load", function () {
      if (this.status !== 403) {
        return;
      }
      try {
        redirectIfRestricted(this.status, JSON.parse(this.responseText));
      } catch (_error) {
        // A non-JSON 403 belongs to another authorization rule.
      }
    });
    return originalSend.apply(this, arguments);
  };
})();
