# Scheming Cookies

## A Problem

Data sent over plaintext HTTP is visible to and can be manipulated by anyone on the network. The
exposure of identifiers like cookies is a particular risk, as it gives attackers both substantial
[monitoring capability][pervasive-monitoring] (see the historical example of
[Google's PREF cookie][PREF-cookie]), and the power to influence otherwise secured traffic by
modifying user state that flows to secure origins.

Cookies' [`Secure` attribute][secure-attr] and the more recent [`__Secure-` prefix][secure-prefix]
mitigate this problem by ensuring that a given cookie will never be leaked to the network, and by
making it more difficult for the network to manipulate its value. Unfortunately, more than a decade
after it's introduction only ~33.58% of cookies are declared with that attribute set. Similarly,
only ~0.18% of cookies carry a `__Secure-` prefix. Though it's likely both numbers will continue to
trend upward, due in part to user agents' imposition of [new requirements on cookies delivered in
third-party contexts][samesite-secure], it's unlikely to reach 100%, meaning that users will
remain vulnerable.

[pervasive-monitoring]: https://tools.ietf.org/html/rfc7258
[PREF-cookie]: https://www.eff.org/deeplinks/2013/12/nsa-turns-cookies-and-more-surveillance-beacons
[secure-attr]: https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis#section-5.3.5
[secure-prefix]: https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis#section-4.1.3.1
[samesite-secure]: https://mikewest.github.io/cookie-incrementalism/draft-west-cookie-incrementalism.html#rfc.section.3.2

## A Proposal

Two changes to cookies could allow us to more robustly insulate secure origins from the network:

1.  **Cookies will be associated with the scheme of the origin from which they're set.** That is,
    cookies set from a given scheme will only be delivered back to that scheme, preventing
    securely-set cookies from leaking to the network, and non-securely set cookies from influencing
    the state of a secure origins. This will also more closely align cookies with the origin model
    that underlies other storage mechanisms on the web.

2.  **Cookies associated with a non-secure scheme will be evicted when a user's session ends**,
    thereby reducing the timespan over which a user broadcasts a stable identifier to the network.

Together, these changes would harden our protections for secure origins, insulating them from the
network. Each deserves a bit more examination.

### Cookies' Scope

Cookies are one of the very few components of the web platform that ignore scheme by default. The
`Secure` attribute can lock a cookie to secure schemes, but cookies lacking that assertion flow
across scheme boundaries, delivered to both the HTTP and HTTPS variants of a given domain, even
though their security properties differ radically. The first change above will remedy this defect,
storing a scheme component along with the cookie, and using that component in cookies' matching
algorithms to ensure that secure and non-secure origins' state is clearly distinguishable and
separate.

This is accomplished as follows: cookies are given an internal `scheme` component, which retains
the value of the scheme from which the cookie was set. If `https://secure.example/` sends
`Set-Cookie: a=b`, that cookie will store "`https`" as its `scheme` component. Likewise,
`http://nonsecure.example/` would store "`http`", and `weird-scheme://weird.example` would store
"`weird-scheme`".

This component would be taken into account when determining whether a cookie matched a cookie
existing in the cookie jar, on the one hand, and when determining whether a cookie matched a
given URL for delivery, on the other. Cookies will be accessible only to the scheme which set them,
matching in this respect the scope of other storage mechanisms available on the web.

Note that this change more or less obviates the `Secure` attribute in favor of an implicit scheme
declaration. It's not clear that there's any real value in changing that attribute's behavior, but
it would no longer be necessary to explicitly declare that a given cookie set from a secure origin
is itself `Secure`.

### Cookies' Lifetime

In the status quo, cookies delivered to non-secure origins are, generally, quite old (see [the
table below](#how-old-are-non-securely-delivered-cookies) for detail). Each cookies' age is somewhat
representative of its risk: long-lived cookies expose persistent identifiers to the network when
delivered non-securely which create tracking opportunities over time. Here, we aim to mitigate this
risk by substantially reducing the lifetime of non-secure cookies, thereby limiting the window of
opportunity for network attackers.

That said, the proposal relies on the notion of a "session", which requires some clarification. We
have several "session" concepts in user agents today, and it's not clear that any of them are
appropriate. HTML's [`sessionStorage`][sessionStorage] lifetime is tied to a particular top-level
browsing context, thereby giving two tabs/windows different views into a page's state. Various user
agents' "private mode" create sessions that are scoped in various ways: Chrome's Incognito mode ties
a session's lifetime to the closure of the last Incognito window, Safari's private mode's lifetime
is tab-specific, etc. Session cookies' lifetime likewise differs between user agents, in some cases
based on user-visible settings like Chrome's "Continue where you left off".

At some risk of [further complicating][xkcd] the notion of a "session", it might be reasonable to
learn from existing user agents' work around meeting users' conceptions of when they're using a
given site. Chromium's [site engagement score][engagement] and Safari's ITP both track a user's last
moment of interaction with a site (which might feasibly include things like navigation, clicks,
scrolls, etc). This seems like a useful bit of data to take into account.

Perhaps we can say that a user has an active session with a given site if one or more documents from
that site are open as top-level browsing contexts, or the timestamp of a user's most recent
interaction with that site is less than an hour ago. (_Note: This definition refers to "site", not
"origin", intentionally because cookies span an entire registrable domain; yes, that's a problem,
no, this document doesn't attempt to address it._) We can use this notion of an active session to
inform the cookie spec's notion of "the current session is over" (the hand-waving claim at the
bottom of [Section 5.4][session-def]), which would be an improvement for session cookies generally,
and give us a clear point at which to remove cookies associated with non-secure schemes.

[sessionStorage]: https://html.spec.whatwg.org/#the-sessionstorage-attribute
[xkcd]: https://xkcd.com/927/
[engagement]: https://www.chromium.org/developers/design-documents/site-engagement
[session-def]: https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis#section-5.4

### Deployment

The changes proposed here seem difficult to do at one fell swoop; developers will need some time to
adjust their servers to ensure that their users are protected. To that end, user agents can move to
this model in stages. For example:

1. User agents can announce the plan, and start poking at developers via devtools and other
   messaging channels. At the same time, user agents can start recording schemes for newly-set
   cookies.

2. To give developers a mechanism which would ensure that existing non-secure state isn't lost,
   user agents can introduce a new, temporary, `Sec-Nonsecure-Cookie` header, which delivers
   non-securely set cookies tied to an HTTP scheme to HTTPS origins that would have matched the
   cookie if the scheme wasn't taken into account.

3. After that's been in place for a reasonable period of time, and developers have written migration
   code depending upon it, user agents can fully implement the first change above, using cookies'
   scheme component to influence cookie matching algorithms. Existing cookies will be delivered only
   to the scheme that set them. We'll continue to deliver cookies tied to an HTTP scheme to the
   matching HTTPS origins via the `Sec-Nonsecure-Cookie` (note: we will not add a JavaScript API to
   access or influence the latter; `document.cookie` will not include cookies whose scheme does not
   match the document).

4. After some appropriate amount of time that allows developers to migrate state from non-secured
   cookies to securely-set cookies, user agents can implement step 2 from above, and begin culling
   non-secure cookies based on session inactivity. Shortly thereafter, the `Sec-Nonsecure-Cookie`
   header can be safely removed, and never spoken of again.

## FAQ

### Why not limit the lifetime of all non-secure storage?

We should absolutely clear all storage for non-secure origins at the same time we clear cookies.
This document doesn't spell that out explicitly only because it seems reasonable to tackle one
problem at a time, and cookies are most dangerous as they're explictly broadcast to the network
and therefore visible to passive observers.

That said, perhaps we should do it all at once to make the message and expectations clear to
developers? I'd be happy to rewrite this proposal if that's the path we decide to take.

### Can we use the Secure attribute rather than a new scheme component?

It's appealing to treat the `Secure` attribute as a "secure scheme"/"non-secure scheme" boolean
that could provide a clear bifurcation of cookies into those delivered to HTTPS vs HTTP
respectively. That approach clearly has some short-term advantages of clarity, and ensures wide
protection for all of a sites' users rather than those using a specific user agent.

While I think that approach has real aesthetic advantages, splitting on scheme allows user agents
to future-proof themselves against the potential introduction of new schemes over time, and to deal
with existing schemes that might conceivably overlap with HTTP and HTTPS, even if they only allow
DOM access to cookies via `document.cookie` (consider `ftp:`, `file:`, `chrome:`, and
`chrome-extension:`, for example). Since we take the scheme into account for all other kinds of
storage, it seems both reasonable and consistent to take it into account here as well.

### Do we need to retain non-secured cookies at all?

It's unlikely that we can completely kill stateful requests over plaintext channels in the same
timeframe that we can ship this proposal. There's a set of non-secure sites that will be difficult
to update, yet also essential to some set of workflows. IoT device management pages (routers, NAS,
printers, etc) will likely still be necessary, and will equally likely be practically unmaintained.

Capping non-secure cookie lifetime to a "session" seems like a reasonable balance between allowing
these pages to be used, while at the same time ensuring that the risk they pose to users is
limited to those times in which they're actively in use.

### The Sec-Nonsecure-Cookie header is weird. Can we do better?

The assumption I'm making here is that developers will not react to public announcements, mailing
list threads, blog posts, Lighthouse scores, devtool warnings, or etc. That's been our experience
with many deprecations over the years; it is simply difficult to get a message out to a zillion
developers.

Given that assumption, `Sec-Nonsecure-Cookie` aims to create an intermediate step between "The
`Cookie` header has all my state!" and "Um. Where'd my state go?!", giving developers an opportunity
to recover data from non-secure origins by porting it over to the secure context.

The explicit addition of a header gives people something to search for (as could synthesizing a
`dear-developer-some-cookies-have-been-eaten=https://explanatory.url/goes/here` cookie value that we
deliver along with the securely-set cookies in the `Cookie` header).

I'm very open to alternative approaches; this one seems reasonable, if strange, but is by no means
set in stone.

### What about intranets?

While intranets really ought to require secure connections, it seems clear that some subset of
companies remain dependent upon plaintext HTTP and/or IP-address-based authentication for internal
communication. Addressing this kind of risk is [beyond the scope of this proposal][beyond]; user
agents would be well-served to create some sort of enterprise configuration that would allow an
administrator to specify a set of origins that ought to be allowed to continue setting non-secure
cookies.

[beyond]: https://cloud.google.com/beyondcorp/

### Doesn't this make users type passwords more often? Isn't that bad?

We should actively discourage folks from typing passwords into non-secure pages. Browsers are moving
on this already by labeling sites as "Not Secure" in various ways when they contain password forms.
I expect that trend to continue, and to act as a counterbalance to the shortened session lifetimes
over HTTP.

### How old are non-securely delivered cookies?

As of December, 2019, cookies delivered to non-secure endpoints are, generally, quite old. The
following table lays out the age in days at various percentiles:

|       | Same-Site | Cross-Site |
|-------|-----------|------------|
| 25%   | 0.7   | 5.2 |
| 50%   | 10.4  | 58  |
| 75%   | 93.9  | 207.4 |
| 95%   | 464.9 | 609.1 |
| 96%   | 522.1 | 661.9 |
| 97%   | 588.6 | 714.5 |
| 98%   | 677.1 | 754.5 |
| 99%   | 761.8 | 823.2 |
| 99.5% | 848.9 | 956.2 |
